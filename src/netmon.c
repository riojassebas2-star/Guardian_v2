#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define TAB_IPS 512
#define MAX_BLOQ 64

typedef struct { int usado; uint32_t ip; uint64_t bytes; } ipent_t;
static ipent_t   g_tab[TAB_IPS];
static long long g_ini = 0;
static char      g_bloq[MAX_BLOQ][INET_ADDRSTRLEN];
static int       g_nbloq = 0;

int net_iniciar(void) {
    int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_IP));
    if (fd < 0) perror("[Guardián] Sensor de red desactivado (AF_PACKET)");
    return fd;
}

/* Rangos que nunca se consideran exfiltración: privadas, loopback, link-local, multicast. */
static int ignorar(uint32_t ip_be) {
    uint32_t a = ntohl(ip_be);
    return a == 0 || a == 0xFFFFFFFFu || (a >> 24) == 10 || (a >> 24) == 127 ||
           (a >> 20) == 0xAC1 || (a >> 16) == 0xC0A8 || (a >> 16) == 0xA9FE || (a >> 28) == 0xE;
}

static void acumular(uint32_t ip, uint64_t bytes) {
    int base = (int)((ip * 2654435761u) % TAB_IPS);
    for (int i = 0; i < TAB_IPS; i++) {
        ipent_t *e = &g_tab[(base + i) % TAB_IPS];
        if (!e->usado) { e->usado = 1; e->ip = ip; e->bytes = bytes; return; }
        if (e->ip == ip) { e->bytes += bytes; return; }
    }
}

void net_procesar(int fd) {
    static unsigned char buf[70000];
    for (int n = 0; n < 512; n++) {
        struct sockaddr_ll sll;
        socklen_t sl = sizeof sll;
        ssize_t r = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&sll, &sl);
        if (r < (ssize_t)sizeof(struct iphdr)) break;
        if (sll.sll_pkttype != PACKET_OUTGOING) continue;
        struct iphdr *ip = (struct iphdr *)buf;
        if (ip->version != 4 || ignorar(ip->daddr)) continue;
        acumular(ip->daddr, (uint64_t)r);
    }
}

/* Ejecuta un comando SIN shell (argumentos en lista): no hay inyección posible. */
static int ejecutar(char *const argv[]) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul >= 0) { dup2(nul, 1); dup2(nul, 2); }
        execvp(argv[0], argv);
        _exit(127);
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* El bloqueo se hace en un proceso hijo: el bucle principal no puede quedarse esperando a
 * iptables mientras hay aperturas de archivos detenidas por los eventos de permiso. */
static int bloquear_ip(const char *ip) {
    int ya = 0;
    for (int i = 0; i < g_nbloq; i++) if (!strcmp(g_bloq[i], ip)) ya = 1;
    if (ya) return 0;
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        char *chk[] = { "iptables", "-w", "-C", "OUTPUT", "-d", (char *)ip, "-j", "DROP", NULL };
        char *add[] = { "iptables", "-w", "-A", "OUTPUT", "-d", (char *)ip, "-j", "DROP", NULL };
        _exit(ejecutar(chk) == 0 ? 0 : ejecutar(add));
    }
    hijo_registrar(p);
    if (g_nbloq < MAX_BLOQ) snprintf(g_bloq[g_nbloq++], INET_ADDRSTRLEN, "%s", ip);
    return 0;
}

/* Al apagar el guardián se retiran las reglas que él mismo creó. */
void net_limpiar(void) {
    for (int i = 0; i < g_nbloq; i++) {
        char *del[] = { "iptables", "-w", "-D", "OUTPUT", "-d", g_bloq[i], "-j", "DROP", NULL };
        ejecutar(del);
    }
    g_nbloq = 0;
}

static void responder(const config_t *c, uint32_t ip, uint64_t bytes) {
    char ipstr[INET_ADDRSTRLEN], exe[PATH_LEN] = "desconocido", desc[PATH_LEN + 64];
    inet_ntop(AF_INET, &ip, ipstr, sizeof ipstr);
    int pid = pi_buscar_pid_ip(ip);
    if (pid > 0) pi_exe(pid, exe, sizeof exe);
    snprintf(desc, sizeof desc, "Tráfico anómalo -> %s (%s)", ipstr, exe);
    long kb = (long)(bytes / 1024);

    if (pid > 0 && wl_confiable(c, exe)) {
        log_alerta(pid, NULL, desc, kb, 0, "SISTEMA / LEGÍTIMO (VERDE)");
        return;
    }
    if (!c->net_bloquear) {
        log_alerta(pid, "RED", desc, kb, 95, "ALERTA EXFILTRACIÓN (SOLO REGISTRO - ROJO)");
        return;
    }
    int ok = bloquear_ip(ipstr) == 0;
    const char *txt = "";
    if (pid > 0 && c->accion != ACC_ALERTA) det_actuar_pid(pid, &txt);
    log_alerta(pid, "RED", desc, kb, 100,
               ok ? "BLOQUEADO (IPTABLES + PROCESO - ROJO)" : "ALERTA EXFILTRACIÓN (FALLÓ IPTABLES - ROJO)");
    det_notificar("Guardián: posible fuga de datos", desc);
}

void net_tick(const config_t *c, long long ahora) {
    if (g_ini == 0) g_ini = ahora;
    if (ahora - g_ini < c->net_ventana_seg) return;
    for (int i = 0; i < TAB_IPS; i++)
        if (g_tab[i].usado && g_tab[i].bytes >= (uint64_t)c->net_umbral_bytes)
            responder(c, g_tab[i].ip, g_tab[i].bytes);
    memset(g_tab, 0, sizeof g_tab);
    g_ini = ahora;
}
