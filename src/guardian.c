/* Guardián Híbrido v2 - motor principal (C puro, un solo bucle poll()).
 *
 *   Archivos  : fanotify A (cierre con escritura, entropía, copia previa) + B (nombres)
 *   Señuelos  : canarios en las carpetas protegidas
 *   Respuesta : SIGSTOP / SIGKILL sobre el ÁRBOL de procesos; re-congela si lo reanudan
 *   Recuperar : bóveda de copias previas  (guardian --restaurar)
 *   Red       : AF_PACKET, bytes salientes por IP pública (+ iptables opcional)
 *   Resiliencia: watchdog de systemd, protección de memoria/OOM, verificación de integridad */
#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>

static config_t g_cfg;

static void uso(void) {
    puts("Guardián Híbrido " GUARDIAN_VERSION "\n"
         "  sudo ./guardian                       inicia el motor\n"
         "  sudo ./guardian --estado              estado del motor en marcha\n"
         "  sudo ./guardian --liberar PID         reanuda un proceso congelado\n"
         "  sudo ./guardian --terminar PID        termina un proceso (y sus hijos)\n"
         "  sudo ./guardian --boveda              resumen de la bóveda\n"
         "  sudo ./guardian --restaurar [--pid N] [--minutos M] [--simular]\n"
         "                                        restaura archivos desde la bóveda");
}

/* ---------------- systemd (sin libsystemd) ---------------- */
static void sd_notificar(const char *msg) {
    const char *p = getenv("NOTIFY_SOCKET");
    struct sockaddr_un a;
    if (!p || !*p) return;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    size_t l = strlen(p);
    if (l >= sizeof a.sun_path) return;
    memcpy(a.sun_path, p, l);
    if (a.sun_path[0] == '@') a.sun_path[0] = '\0';
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    if (sendto(fd, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&a,
               (socklen_t)(offsetof(struct sockaddr_un, sun_path) + l)) < 0) { /* sin systemd */ }
    close(fd);
}

/* ---------------- arranque ---------------- */
static void endurecer(void) {
    prctl(PR_SET_DUMPABLE, 0);              /* nadie puede leer su memoria ni adjuntarle ptrace */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) { if (write(fd, "-1000", 5) < 0) { /* sin permiso */ } close(fd); }
    mlockall(MCL_CURRENT | MCL_FUTURE);     /* sin paginación: sigue respondiendo bajo presión de memoria */
}

static void preparar_dirs(void) {
    for (int i = 0; i < g_cfg.n_dirs; i++) {
        const char *d = g_cfg.watch_dirs[i];
        struct stat st;
        if (stat(d, &st) == 0) continue;
        if (!strncmp(d, "/tmp/", 5) && mkdir(d, 0775) == 0) {      /* solo se crean carpetas de prueba */
            if (chown(d, g_cfg.owner_uid, g_cfg.owner_gid) != 0) { /* no crítico */ }
        } else fprintf(stderr, "[Guardián] La carpeta %s no existe: se omite.\n", d);
    }
}

static void escribir_pid(void) {
    int fd = open(g_cfg.pid_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return;
    char t[32];
    int n = snprintf(t, sizeof t, "%d\n", getpid());
    if (write(fd, t, (size_t)n) < 0) { /* no crítico */ }
    if (fchown(fd, g_cfg.owner_uid, g_cfg.owner_gid) != 0) { /* no crítico */ }
    close(fd);
}

static int propias_fuera_de_vigilancia(void) {
    const char *rutas[] = { g_cfg.log_file, g_cfg.vault_dir, g_cfg.pid_file, g_cfg.sock_file };
    for (int i = 0; i < 4; i++)
        if (ruta_bajo_dirs(&g_cfg, rutas[i])) {
            fprintf(stderr, "[Guardián] %s está dentro de una carpeta vigilada: provocaría un bloqueo.\n", rutas[i]);
            return 0;
        }
    return 1;
}

static int cliente(int argc, char **argv, const config_t *c) {
    int pid = 0, minutos = 0, simular = 0;
    const char *accion = argv[1];
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc) pid = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--minutos") && i + 1 < argc) minutos = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--simular")) simular = 1;
        else if (i == 2 && (!strcmp(accion, "--liberar") || !strcmp(accion, "--terminar"))) pid = atoi(argv[i]);
    }
    if (geteuid() != 0) { fprintf(stderr, "Este comando requiere root: usa sudo.\n"); return 1; }
    char cmd[64];
    if (!strcmp(accion, "--estado"))    return ctl_cliente(c, "estado");
    if (!strcmp(accion, "--liberar") && pid > 1)  { snprintf(cmd, sizeof cmd, "liberar %d", pid); return ctl_cliente(c, cmd); }
    if (!strcmp(accion, "--terminar") && pid > 1) { snprintf(cmd, sizeof cmd, "terminar %d", pid); return ctl_cliente(c, cmd); }
    if (!strcmp(accion, "--boveda"))    return bov_estado_cli(c);
    if (!strcmp(accion, "--restaurar")) return bov_restaurar_cli(c, pid, minutos, simular);
    uso();
    return 1;
}

int main(int argc, char **argv) {
    char home[PATH_LEN], conf_dir[PATH_LEN];
    int sistema;
    config_ubicar(home, sizeof home, conf_dir, sizeof conf_dir, &sistema);

    if (argc > 1) {
        if (!strcmp(argv[1], "--version")) { puts("Guardián Híbrido " GUARDIAN_VERSION); return 0; }
        if (!strcmp(argv[1], "--ayuda") || !strcmp(argv[1], "-h")) { uso(); return 0; }
        if (config_cargar(&g_cfg, home, conf_dir, sistema) != 0) return 1;
        return cliente(argc, argv, &g_cfg);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "El Guardián necesita root (fanotify, AF_PACKET): sudo ./guardian\n");
        return 1;
    }
    if (config_cargar(&g_cfg, home, conf_dir, sistema) != 0) return 1;
    int malos = config_permisos(&g_cfg);
    if (malos && sistema) { fprintf(stderr, "[Guardián] Configuración insegura: se niega a arrancar.\n"); return 1; }
    if (!propias_fuera_de_vigilancia()) return 1;

    char exe_propio[PATH_LEN], sha_inicio[65] = "", sha_ahora[65];
    ssize_t l = readlink("/proc/self/exe", exe_propio, sizeof exe_propio - 1);
    if (l <= 0) { perror("readlink"); return 1; }
    exe_propio[l] = '\0';
    sha256_archivo("/proc/self/exe", sha_inicio);

    endurecer();
    det_iniciar(&g_cfg, exe_propio);
    if (log_abrir(g_cfg.log_file, g_cfg.owner_uid, g_cfg.owner_gid) != 0) return 1;
    preparar_dirs();
    canarios_asegurar(&g_cfg);                  /* antes de activar los monitores: sin eventos propios */
    if (bov_iniciar(&g_cfg) != 0) return 1;
    if (mon_iniciar(&g_cfg) != 0) return 1;
    mon_marcar_todo();
    int fd_net = g_cfg.net_activo ? net_iniciar() : -1;

    sigset_t ms;
    sigemptyset(&ms);
    sigaddset(&ms, SIGINT); sigaddset(&ms, SIGTERM); sigaddset(&ms, SIGHUP);
    sigprocmask(SIG_BLOCK, &ms, NULL);
    signal(SIGPIPE, SIG_IGN);
    int fd_sig = signalfd(-1, &ms, SFD_NONBLOCK | SFD_CLOEXEC);
    int fd_tim = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec it = { { 1, 0 }, { 1, 0 } };
    timerfd_settime(fd_tim, 0, &it, NULL);
    int fd_ctl = ctl_iniciar(&g_cfg);

    escribir_pid();
    printf("[Guardián %s] pid %d | archivos: %s%s | carpetas: %d | canarios: %s | bóveda: %s | red: %s | acción: %s\n",
           GUARDIAN_VERSION, getpid(), "fanotify A", mon_fd_b() >= 0 ? "+B" : "",
           g_cfg.n_dirs, g_cfg.canarios ? "sí" : "no", g_cfg.boveda ? "sí" : "no",
           fd_net >= 0 ? (g_cfg.net_bloquear ? "bloquear" : "alerta") : "apagada",
           g_cfg.accion == ACC_CONGELAR ? "congelar" : g_cfg.accion == ACC_TERMINAR ? "terminar" : "alerta");
    fflush(stdout);
    log_alerta(0, "SISTEMA", "Guardián iniciado", g_cfg.n_dirs, 0, "SISTEMA / GUARDIÁN INICIADO (VERDE)");
    sd_notificar("READY=1");

    long wd_usec = getenv("WATCHDOG_USEC") ? atol(getenv("WATCHDOG_USEC")) : 0;
    long wd_cada = wd_usec > 0 ? (wd_usec / 2000000L > 0 ? wd_usec / 2000000L : 1) : 0;

    struct pollfd fds[6] = { { mon_fd_a(), POLLIN, 0 }, { mon_fd_b(), POLLIN, 0 }, { fd_net, POLLIN, 0 },
                             { fd_tim, POLLIN, 0 }, { fd_sig, POLLIN, 0 }, { fd_ctl, POLLIN, 0 } };
    int salir = 0, integridad_avisada = 0;
    long long ticks = 0;
    while (!salir) {
        if (poll(fds, 6, -1) < 0 && errno != EINTR) break;
        /* A se lee primero y se aplaza; B (creaciones) se lee después; luego se procesa A.
         * Así todo CLOSE_WRITE visto tiene ya su CREATE disponible en el grupo B. */
        int hubo_a = fds[0].revents & POLLIN;
        if (hubo_a) mon_leer_a();
        if (hubo_a || (fds[1].revents & POLLIN)) mon_leer_b();
        mon_vaciar_a();
        if (fds[2].revents & POLLIN) net_procesar(fd_net);
        if (fds[5].revents & POLLIN) ctl_atender(fd_ctl);
        if (fds[3].revents & POLLIN) {
            uint64_t exp;
            if (read(fd_tim, &exp, sizeof exp) < 0) { /* nada */ }
            long long t = mono_seg();
            ticks++;
            hijos_cosechar();
            det_tick(t);
            bov_tick(t);
            if (config_whitelist_refrescar(&g_cfg))
                log_alerta(0, "SISTEMA", "Lista blanca modificada", g_cfg.n_wl, 40, "LISTA BLANCA MODIFICADA (AMARILLO)");
            if (fd_net >= 0) net_tick(&g_cfg, t);
            if (g_cfg.audit_dpkg && ticks % 3 == 0) audit_dpkg_tick();
            if (mon_rescan_pendiente() || ticks % 30 == 0) mon_marcar_todo();
            if (ticks % 60 == 0) canarios_asegurar_async(&g_cfg);
            if (ticks % 60 == 0 && !integridad_avisada) {         /* ¿alguien cambió el binario en disco? */
                if (sha256_archivo(exe_propio, sha_ahora) != 0 || strcmp(sha_ahora, sha_inicio) != 0) {
                    integridad_avisada = 1;
                    log_alerta(0, "SISTEMA", "El binario del guardián cambió o desapareció del disco",
                               0, 100, "ALERTA DE INTEGRIDAD (ROJO)");
                }
            }
            if (wd_cada && ticks % wd_cada == 0) sd_notificar("WATCHDOG=1");
        }
        if (fds[4].revents & POLLIN) {
            struct signalfd_siginfo si;
            while (read(fd_sig, &si, sizeof si) == (ssize_t)sizeof si) {
                if (si.ssi_signo == SIGHUP) { g_cfg.wl_mtime = -1; config_whitelist_refrescar(&g_cfg); }
                else salir = 1;
            }
        }
    }
    sd_notificar("STOPPING=1");
    log_alerta(0, "SISTEMA", "Guardián detenido", 0, 0, "SISTEMA / GUARDIÁN DETENIDO (VERDE)");
    net_limpiar();
    ctl_cerrar(&g_cfg);
    mon_cerrar();                                /* al cerrar, el núcleo libera aperturas pendientes */
    unlink(g_cfg.pid_file);
    log_cerrar();
    printf("[Guardián] Detenido.\n");
    return 0;
}
