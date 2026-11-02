/* Detección por comportamiento y respuesta.
 *
 * Por cada proceso y ventana de tiempo se acumulan señales:
 *   ritmo     reescritura de archivos PREEXISTENTES (no cuenta crear archivos nuevos)
 *   cifrado   escrituras con entropía alta y sin firma de formato conocido
 *   renombres cambios de nombre que agregan sufijo o usan extensiones de ransomware
 *   nota      creación de archivos con nombre de nota de rescate
 *   canario   cualquier escritura/renombrado de un archivo señuelo (100 puntos directos)
 * Más amplificadores: borrados masivos, varias señales a la vez y origen sospechoso
 * del ejecutable (/tmp, memfd, borrado). */
#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <ctype.h>

static const config_t *C;
static char g_exe[PATH_LEN];
static long long g_eventos, g_criticas;

#define MAX_ARBOL 256
#define MAX_CONG  128

/* ---------------- registro de procesos congelados ---------------- */
typedef struct { int pid; unsigned long long inicio; long long ult_log; } cong_t;
static cong_t g_cong[MAX_CONG];
static int    g_ncong;

static void cong_add(int pid) {
    unsigned long long ini = 0;
    if (pi_stat(pid, NULL, NULL, &ini) != 0) return;
    for (int i = 0; i < g_ncong; i++)
        if (g_cong[i].pid == pid && g_cong[i].inicio == ini) return;
    if (g_ncong < MAX_CONG) g_cong[g_ncong++] = (cong_t){ pid, ini, 0 };
}

static void cong_quitar(int pid) {
    for (int i = 0; i < g_ncong; i++)
        if (g_cong[i].pid == pid) { g_cong[i] = g_cong[--g_ncong]; return; }
}

static int arbol(int raiz, int *lista) {
    lista[0] = raiz;
    return 1 + pi_descendientes(raiz, lista + 1, MAX_ARBOL - 1);
}

static int valido(int pid) { return pid > 1 && pid != getpid(); }

static int congelar_arbol(int raiz) {
    int l[MAX_ARBOL], ok = 0, n = arbol(raiz, l);
    for (int i = 0; i < n; i++)
        if (valido(l[i]) && kill(l[i], SIGSTOP) == 0) { cong_add(l[i]); ok++; }
    return ok;
}

static int terminar_arbol(int raiz) {
    int l[MAX_ARBOL], ok = 0, n = arbol(raiz, l);
    for (int i = 0; i < n; i++) if (valido(l[i])) kill(l[i], SIGSTOP);   /* que no sigan forkeando */
    for (int i = 0; i < n; i++)
        if (valido(l[i]) && kill(l[i], SIGKILL) == 0) { cong_quitar(l[i]); ok++; }
    return ok;
}

int det_actuar_pid(int pid, const char **texto) {
    if (C->accion == ACC_TERMINAR) { *texto = "TERMINADO (SIGKILL - ROJO)"; return terminar_arbol(pid); }
    if (C->accion == ACC_ALERTA)   { *texto = "ALERTA (SOLO REGISTRO - ROJO)"; return 1; }
    *texto = "CONGELADO (SIGSTOP - ROJO)";
    return congelar_arbol(pid);
}

/* ---------------- notificación de escritorio (sin shell) ---------------- */
void det_notificar(const char *titulo, const char *cuerpo) {
    static long long ultima = 0;
    if (!C || !C->notificar || C->owner_uid == 0) return;
    long long t = mono_seg();
    if (t - ultima < 10) return;
    ultima = t;
    pid_t p = fork();
    if (p < 0) return;
    if (p == 0) {
        if (setgroups(0, NULL) != 0 || setgid(C->owner_gid) != 0 || setuid(C->owner_uid) != 0) _exit(1);
        char rt[64], bus[96];
        snprintf(rt, sizeof rt, "/run/user/%u", (unsigned)C->owner_uid);
        snprintf(bus, sizeof bus, "unix:path=%s/bus", rt);
        setenv("XDG_RUNTIME_DIR", rt, 1);
        setenv("DBUS_SESSION_BUS_ADDRESS", bus, 1);
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        execlp("notify-send", "notify-send", "-u", "critical", "-a", "Guardián", titulo, cuerpo, (char *)NULL);
        _exit(127);
    }
    hijo_registrar(p);
}

/* ---------------- confianza por proceso (con caché de 10 s) ---------------- */
typedef struct { int pid, ok; long long t; } cache_t;
static cache_t g_cache[128];

int det_pid_confiable(int pid) {
    long long t = mono_seg();
    cache_t *c = &g_cache[(unsigned)pid % 128];
    if (c->pid == pid && t - c->t < 10) return c->ok;
    char exe[PATH_LEN];
    int ok = 0;
    if (pid == getpid() || hijo_es(pid)) ok = 1;
    else if (pi_exe(pid, exe, sizeof exe) == 0) ok = !strcmp(exe, g_exe) || wl_confiable(C, exe);
    c->pid = pid; c->ok = ok; c->t = t;
    return ok;
}

/* ---------------- utilidades de nombres ---------------- */
static const char *EXT_SOSP[] = { "locked", "locked_test", "enc", "encrypted", "crypt", "crypted",
    "crypto", "cry", "zepto", "locky", "cerber", "wncry", "wnry", "petya", "ryk", "ryuk", "conti",
    "lockbit", "akira", "royal", "blackcat", "hive", "babuk", "djvu", "stop", "ecc", "vault",
    "crypz", "pays", "xtbl", "kraken", "rdm", "hacked", NULL };

static const char *NOTAS[] = { "decrypt", "ransom", "recover_your", "recover-your", "restore_your",
    "restore-your", "restore_my", "restore-my", "your_files", "your-files", "unlock_files",
    "read_me_to", "readme_to", "hacked", NULL };

static void minusculas(const char *s, char *o, size_t n) {
    size_t i = 0;
    for (; s[i] && i + 1 < n; i++) o[i] = (char)tolower((unsigned char)s[i]);
    o[i] = '\0';
}

static int ext_sospechosa(const char *nombre) {
    const char *p = strrchr(nombre, '.');
    if (!p || !p[1]) return 0;
    char e[32];
    minusculas(p + 1, e, sizeof e);
    for (int i = 0; EXT_SOSP[i]; i++) if (!strcmp(e, EXT_SOSP[i])) return 1;
    return 0;
}

static int es_nota(const char *nombre) {
    char m[NOMBRE_MAX];
    minusculas(nombre, m, sizeof m);
    for (int i = 0; NOTAS[i]; i++) if (strstr(m, NOTAS[i])) return 1;
    return 0;
}

/* Renombre sospechoso: se AGREGA un sufijo al nombre (doc.txt -> doc.txt.xyz)
 * o el nuevo nombre usa una extensión típica de ransomware. */
static int ren_sospechoso(const char *viejo, const char *nuevo) {
    size_t lv = strlen(viejo);
    if (strlen(nuevo) > lv && !strncmp(nuevo, viejo, lv) && nuevo[lv] == '.') return 1;
    return ext_sospechosa(nuevo);
}

/* ---------------- puntaje ---------------- */
typedef enum { EV_ESCR, EV_CREA, EV_BORRA, EV_DESDE, EV_HACIA, EV_CAN_W, EV_CAN_D } evtipo_t;
typedef struct { evtipo_t t; uint64_t clave; char nombre[NOMBRE_MAX]; int cifrado, reciente; } ev_t;

static void actualizar(pidstat_t *st, const ev_t *ev) {
    uint32_t h = hash_nombre(ev->nombre);
    st->total++;
    switch (ev->t) {
    case EV_CREA:
        pt_add_creado(st, h);
        if (es_nota(ev->nombre)) st->notas++;
        if (ext_sospechosa(ev->nombre)) st->renombres++;
        break;
    case EV_ESCR:
        if (ev->reciente || pt_es_creado(st, h)) st->nuevos++;
        else { st->escrituras++; pt_inodo(st, ev->clave); }
        if (ev->cifrado) st->cifrados++;
        break;
    case EV_BORRA:
        if (!pt_es_creado(st, h)) st->borrados++;
        break;
    case EV_DESDE:
        snprintf(st->ult_from, sizeof st->ult_from, "%s", ev->nombre);
        break;
    case EV_HACIA:
        if (st->ult_from[0]) {
            if (ren_sospechoso(st->ult_from, ev->nombre)) st->renombres++;
            st->ult_from[0] = '\0';
        } else if (ext_sospechosa(ev->nombre)) st->renombres++;
        if (es_nota(ev->nombre)) st->notas++;
        break;
    case EV_CAN_W: st->canario = 1; break;
    case EV_CAN_D: if (!st->canario) st->canario = 2; break;
    }
}

static void agregar(char *s, size_t n, const char *x) {
    if (s[0]) strncat(s, ",", n - strlen(s) - 1);
    strncat(s, x, n - strlen(s) - 1);
}

static int min100(int v) { return v > 100 ? 100 : v; }

static int puntaje(const pidstat_t *st, int real, char *sen, size_t ns) {
    int T = C->umbral_eventos, d3 = T / 3 ? T / 3 : 1, d2 = T / 2 ? T / 2 : 1;
    int s_rit = min100(st->escrituras * 100 / T);
    if (st->n_inodos < C->umbral_archivos && s_rit > 60) s_rit = 60;   /* muchas escrituras, pocos archivos */
    int s_cif = min100(st->cifrados * 100 / d3);
    int s_ren = min100(st->renombres * 100 / d2);
    int s_not = st->notas >= 2 ? 100 : st->notas == 1 ? 70 : 0;
    int base = s_rit;
    if (s_cif > base) base = s_cif;
    if (s_ren > base) base = s_ren;
    if (s_not > base) base = s_not;
    sen[0] = '\0';
    int fuertes = 0;
    if (s_rit >= 50) { agregar(sen, ns, "ritmo");     fuertes++; }
    if (s_cif >= 50) { agregar(sen, ns, "cifrado");   fuertes++; }
    if (s_ren >= 50) { agregar(sen, ns, "renombres"); fuertes++; }
    if (s_not >= 50) { agregar(sen, ns, "nota");      fuertes++; }
    if (st->borrados >= d2 && base >= 30) { base += 20; agregar(sen, ns, "borrados"); }
    if (fuertes >= 2) base += 15;
    if (base >= 30 && base < 100 && real > 1) {
        char exe[PATH_LEN];
        if (pi_exe(real, exe, sizeof exe) == 0 && pi_origen_sospechoso(exe)) { base += 30; agregar(sen, ns, "origen"); }
    }
    if (st->canario == 1) { base = 100; agregar(sen, ns, "canario"); }
    else if (st->canario == 2) { if (base < 60) base = 60; agregar(sen, ns, "canario-borrado"); }
    return base > 100 ? 100 : base;
}

/* ---------------- respuesta ---------------- */
static void responder(const pidstat_t *st, int real, int p, const char *sen, int es_arbol) {
    char exe[PATH_LEN], accion[320];
    if (!valido(real)) return;
    if (pi_exe(real, exe, sizeof exe) != 0) {
        snprintf(accion, sizeof accion, "ALERTA (EL PROCESO YA TERMINÓ - ROJO) [%s]", sen);
        log_alerta(real, NULL, "Proceso ya terminado", st->total, p, accion);
        return;
    }
    if (det_pid_confiable(real)) {
        log_alerta(real, NULL, exe, st->total, 0, "SISTEMA / LEGÍTIMO (VERDE)");
        return;
    }
    const char *txt;
    int n = det_actuar_pid(real, &txt);
    if (n == 0) txt = "ALERTA (NO SE PUDO ACTUAR - ROJO)";
    snprintf(accion, sizeof accion, "%s [%s]%s", txt, sen, es_arbol ? " (árbol)" : "");
    log_alerta(real, NULL, exe, st->total, p, accion);
    g_criticas++;
    const char *base = strrchr(exe, '/');
    char cuerpo[800];
    snprintf(cuerpo, sizeof cuerpo, "%s (pid %d): %s", base ? base + 1 : exe, real, sen);
    det_notificar("Guardián: actividad tipo ransomware", cuerpo);
}

static void evaluar(pidstat_t *st, int real, int es_arbol, long long ahora) {
    if (ahora < st->perdon_hasta) return;
    char sen[160];
    int p = puntaje(st, real, sen, sizeof sen);
    if (p >= C->umbral_critico) {
        if (!st->actuado) { st->actuado = 1; responder(st, real, p, sen, es_arbol); }
    } else if (p >= 60 && !st->avisado && !es_arbol) {
        char exe[PATH_LEN], accion[240];
        if (pi_exe(real, exe, sizeof exe) != 0) snprintf(exe, sizeof exe, "proceso desconocido");
        st->avisado = 1;
        snprintf(accion, sizeof accion, "ACTIVIDAD SOSPECHOSA (AMARILLO) [%s]", sen);
        log_alerta(real, NULL, exe, st->total, p, accion);
    }
}

/* El padre se agrega solo si no es un intérprete de comandos ni algo de confianza:
 * así un ataque repartido entre procesos hijos se suma en el padre. */
static void preparar_padre(pidstat_t *st, int pid) {
    char exe[PATH_LEN];
    st->ppid_listo = 1;
    st->ppid = pi_ppid(pid);
    if (st->ppid > 1 && st->ppid != getpid() && pi_exe(st->ppid, exe, sizeof exe) == 0 &&
        !pi_es_shell(exe) && !det_pid_confiable(st->ppid))
        st->agrega_padre = 1;
}

static void despachar(int pid, const ev_t *ev) {
    if (pid <= 1 || pid == getpid() || hijo_es(pid) || det_pid_confiable(pid)) return;
    long long t = mono_seg();
    g_eventos++;
    pidstat_t *st = pt_obtener(pid, t);
    pt_ventana(st, t, C->ventana_seg);
    if (!st->ppid_listo) preparar_padre(st, pid);
    actualizar(st, ev);
    evaluar(st, pid, 0, t);
    int agrega = st->agrega_padre, ppid = st->ppid;      /* st puede invalidarse al pedir otra entrada */
    if (agrega) {
        pidstat_t *pp = pt_obtener(-ppid, t);
        pt_ventana(pp, t, C->ventana_seg);
        actualizar(pp, ev);
        evaluar(pp, ppid, 1, t);
    }
}

void det_escritura(int pid, uint64_t clave, const char *nombre, int cifrado, int reciente) {
    ev_t e = { EV_ESCR, clave, "", cifrado, reciente };
    snprintf(e.nombre, sizeof e.nombre, "%s", nombre);
    despachar(pid, &e);
}
static void simple(int pid, evtipo_t t, const char *nombre) {
    ev_t e = { t, 0, "", 0, 0 };
    snprintf(e.nombre, sizeof e.nombre, "%s", nombre);
    despachar(pid, &e);
}
void det_creacion(int pid, const char *n)   { simple(pid, EV_CREA, n); }
void det_borrado(int pid, const char *n)    { simple(pid, EV_BORRA, n); }
void det_mov_desde(int pid, const char *n)  { simple(pid, EV_DESDE, n); }
void det_mov_hacia(int pid, const char *n)  { simple(pid, EV_HACIA, n); }
void det_canario(int pid, const char *n, int borrado) { simple(pid, borrado ? EV_CAN_D : EV_CAN_W, n); }

/* ---------------- ciclo de vida y control ---------------- */
void det_iniciar(const config_t *c, const char *exe_propio) {
    C = c;
    snprintf(g_exe, sizeof g_exe, "%s", exe_propio);
}

/* Un proceso congelado que alguien reanuda (SIGCONT) se vuelve a congelar. */
void det_tick(long long ahora) {
    pt_purgar(ahora, 60);
    for (int i = 0; i < g_ncong; ) {
        char st; unsigned long long ini;
        if (pi_stat(g_cong[i].pid, &st, NULL, &ini) != 0 || ini != g_cong[i].inicio) {
            g_cong[i] = g_cong[--g_ncong];
            continue;
        }
        if (st != 'T' && st != 't' && st != 'Z' && st != 'X') {
            kill(g_cong[i].pid, SIGSTOP);
            if (ahora - g_cong[i].ult_log >= 10) {
                char exe[PATH_LEN] = "desconocido";
                g_cong[i].ult_log = ahora;
                pi_exe(g_cong[i].pid, exe, sizeof exe);
                log_alerta(g_cong[i].pid, NULL, exe, 0, 100, "RE-CONGELADO (ALGUIEN LO REANUDÓ - ROJO)");
            }
        }
        i++;
    }
}

static void perdonar(int pid, long long hasta) {
    long long t = mono_seg();
    pt_obtener(pid, t)->perdon_hasta = hasta;
    pt_obtener(-pid, t)->perdon_hasta = hasta;
}

int det_liberar(int pid, char *msg, size_t n) {
    int hay = 0;
    for (int i = 0; i < g_ncong; i++) if (g_cong[i].pid == pid) hay = 1;
    if (!hay) { snprintf(msg, n, "El proceso %d no está congelado por el guardián.", pid); return -1; }
    int l[MAX_ARBOL], k = arbol(pid, l), liberados = 0;
    char exe[PATH_LEN] = "desconocido";
    pi_exe(pid, exe, sizeof exe);
    for (int i = 0; i < k; i++) {
        if (!valido(l[i])) continue;
        cong_quitar(l[i]);
        if (kill(l[i], SIGCONT) == 0) liberados++;
    }
    perdonar(pid, mono_seg() + 120);
    log_alerta(pid, NULL, exe, liberados, 0, "SISTEMA / LIBERADO MANUALMENTE (VERDE)");
    snprintf(msg, n, "Liberados %d proceso(s). Sin vigilancia sobre %d durante 120 s.", liberados, pid);
    return 0;
}

int det_terminar(int pid, char *msg, size_t n) {
    if (!valido(pid)) { snprintf(msg, n, "PID no válido."); return -1; }
    char exe[PATH_LEN] = "desconocido";
    pi_exe(pid, exe, sizeof exe);
    int k = terminar_arbol(pid);
    if (k == 0) { snprintf(msg, n, "No se pudo terminar el proceso %d.", pid); return -1; }
    log_alerta(pid, NULL, exe, k, 0, "SISTEMA / TERMINADO MANUALMENTE (VERDE)");
    snprintf(msg, n, "Terminados %d proceso(s).", k);
    return 0;
}

void det_estado(char *out, size_t n) {
    int o = snprintf(out, n, "Eventos procesados: %lld | detecciones críticas: %lld | congelados: %d\n",
                     g_eventos, g_criticas, g_ncong);
    for (int i = 0; i < g_ncong && o > 0 && (size_t)o < n; i++) {
        char exe[PATH_LEN] = "?";
        pi_exe(g_cong[i].pid, exe, sizeof exe);
        o += snprintf(out + o, n - (size_t)o, "  pid %d  %s\n", g_cong[i].pid, exe);
    }
}
