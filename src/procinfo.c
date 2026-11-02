#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/wait.h>

long long mono_seg(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

int pi_exe(int pid, char *out, size_t n) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/exe", pid);
    ssize_t l = readlink(p, out, n - 1);
    if (l < 0) return -1;
    out[l] = '\0';
    return 0;
}

/* /proc/<pid>/stat: "pid (comm) estado ppid ... inicio(campo 22)". El nombre puede
 * contener paréntesis, por eso se busca el ÚLTIMO ')'. */
int pi_stat(int pid, char *estado, int *ppid, unsigned long long *inicio) {
    char ruta[64], buf[1024];
    snprintf(ruta, sizeof ruta, "/proc/%d/stat", pid);
    FILE *f = fopen(ruta, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    char st; int pp; unsigned long long ini = 0;
    if (sscanf(p + 2, "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu",
               &st, &pp, &ini) < 2) return -1;
    if (estado) *estado = st;
    if (ppid) *ppid = pp;
    if (inicio) *inicio = ini;
    return 0;
}

int pi_ppid(int pid) {
    int pp = 0;
    return pi_stat(pid, NULL, &pp, NULL) == 0 ? pp : 0;
}

static int es_numero(const char *s) {
    if (!*s) return 0;
    for (; *s; s++) if (*s < '0' || *s > '9') return 0;
    return 1;
}

/* Descendientes (hijos, nietos...) de un proceso, por recorrido en anchura.
 * Devuelve cuántos encontró y los deja en out (sin incluir al propio pid). */
int pi_descendientes(int pid, int *out, int max) {
    enum { MAXP = 16384, COLA = 4096 };
    static int pids[MAXP], pps[MAXP];
    int cola[COLA];
    int np = 0, n = 0;
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) && np < MAXP) {
        if (!es_numero(e->d_name)) continue;
        int p = atoi(e->d_name), pp;
        if (pi_stat(p, NULL, &pp, NULL) == 0) { pids[np] = p; pps[np] = pp; np++; }
    }
    closedir(d);
    int cabeza = 0, fin = 0;
    cola[fin++] = pid;
    while (cabeza < fin && n < max) {
        int actual = cola[cabeza++];
        for (int i = 0; i < np && n < max; i++) {
            if (pps[i] != actual || pids[i] == pid) continue;
            out[n++] = pids[i];
            if (fin < COLA) cola[fin++] = pids[i];
        }
    }
    return n;
}

int pi_es_shell(const char *exe) {
    static const char *shells[] = { "bash", "sh", "dash", "zsh", "fish", "ksh", "csh", "tcsh",
        "sudo", "su", "login", "sshd", "tmux", "screen", "systemd", "init",
        "gnome-terminal-server", "konsole", "xterm", "kitty", "alacritty", NULL };
    const char *b = strrchr(exe, '/');
    b = b ? b + 1 : exe;
    for (int i = 0; shells[i]; i++) if (!strcmp(b, shells[i])) return 1;
    return 0;
}

/* Ejecutables lanzados desde lugares donde un programa legítimo casi nunca vive. */
int pi_origen_sospechoso(const char *exe) {
    static const char *malos[] = { "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", NULL };
    for (int i = 0; malos[i]; i++) if (!strncmp(exe, malos[i], strlen(malos[i]))) return 1;
    if (strstr(exe, "memfd:")) return 1;
    size_t l = strlen(exe);
    return l >= 10 && !strcmp(exe + l - 10, " (deleted)");
}

/* ---- dueño de una conexión: tablas de /proc/net -> inodo -> descriptores de cada proceso ---- */
static int pid_con_socket(unsigned long inodo) {
    char objetivo[64], ruta[PATH_LEN], enlace[128];
    snprintf(objetivo, sizeof objetivo, "socket:[%lu]", inodo);
    DIR *proc = opendir("/proc");
    if (!proc) return -1;
    struct dirent *e;
    int hallado = -1;
    while (hallado < 0 && (e = readdir(proc))) {
        if (!es_numero(e->d_name)) continue;
        snprintf(ruta, sizeof ruta, "/proc/%s/fd", e->d_name);
        DIR *fd = opendir(ruta);
        if (!fd) continue;
        struct dirent *f;
        while ((f = readdir(fd))) {
            char enl[PATH_LEN + 300];
            snprintf(enl, sizeof enl, "%s/%s", ruta, f->d_name);
            ssize_t l = readlink(enl, enlace, sizeof enlace - 1);
            if (l <= 0) continue;
            enlace[l] = '\0';
            if (!strcmp(enlace, objetivo)) { hallado = atoi(e->d_name); break; }
        }
        closedir(fd);
    }
    closedir(proc);
    return hallado;
}

int pi_buscar_pid_ip(uint32_t ip_be) {
    static const char *tablas[] = { "/proc/net/tcp", "/proc/net/udp", NULL };
    char linea[512];
    for (int t = 0; tablas[t]; t++) {
        FILE *f = fopen(tablas[t], "r");
        if (!f) continue;
        if (!fgets(linea, sizeof linea, f)) { fclose(f); continue; }
        while (fgets(linea, sizeof linea, f)) {
            unsigned rem; unsigned long inodo;
            if (sscanf(linea, "%*d: %*X:%*X %X:%*X %*X %*X:%*X %*X:%*X %*X %*u %*u %lu",
                       &rem, &inodo) != 2) continue;
            if (rem != ip_be || inodo == 0) continue;
            int pid = pid_con_socket(inodo);
            if (pid > 0) { fclose(f); return pid; }
        }
        fclose(f);
    }
    return -1;
}

/* ---- procesos hijos del propio guardián (canarios, avisos): sus eventos se ignoran ---- */
static int g_hijos[32], g_nh;

void hijo_registrar(int pid) { if (g_nh < 32) g_hijos[g_nh++] = pid; }

int hijo_es(int pid) {
    for (int i = 0; i < g_nh; i++) if (g_hijos[i] == pid) return 1;
    return 0;
}

void hijos_cosechar(void) {
    int st, p;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0)
        for (int i = 0; i < g_nh; i++)
            if (g_hijos[i] == p) { g_hijos[i] = g_hijos[--g_nh]; break; }
}
