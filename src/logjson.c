#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define LOG_MAX_BYTES (5L * 1024 * 1024)

static int  g_fd = -1;
static char g_ruta[PATH_LEN];
static uid_t g_uid;
static gid_t g_gid;

/* Escapa comillas, barras y caracteres de control: el JSON siempre es válido. */
static void escapar(const char *s, char *out, size_t n) {
    size_t j = 0;
    for (; *s && j + 7 < n; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') { out[j++] = '\\'; out[j++] = (char)ch; }
        else if (ch < 0x20)          { j += (size_t)snprintf(out + j, n - j, "\\u%04x", ch); }
        else                          out[j++] = (char)ch;
    }
    out[j] = '\0';
}

static int abrir(void) {
    /* O_NOFOLLOW: el guardián corre como root y el log está en una carpeta del
     * usuario; así nadie puede redirigirlo con un enlace simbólico. */
    g_fd = open(g_ruta, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (g_fd < 0) { perror("[Guardián] No se pudo abrir el log"); return -1; }
    if (fchown(g_fd, g_uid, g_gid) != 0) { /* no crítico */ }
    return 0;
}

int log_abrir(const char *ruta, uid_t uid, gid_t gid) {
    snprintf(g_ruta, sizeof g_ruta, "%s", ruta);
    g_uid = uid; g_gid = gid;
    char dir[PATH_LEN];
    snprintf(dir, sizeof dir, "%s", ruta);
    char *barra = strrchr(dir, '/');
    if (barra && barra != dir) {
        *barra = '\0';
        if (mkdir(dir, 0755) == 0 && chown(dir, uid, gid) != 0) { /* no crítico */ }
    }
    return abrir();
}

void log_alerta(int pid, const char *etiqueta, const char *programa,
                long volumen, int puntaje, const char *accion) {
    if (g_fd < 0) return;
    struct stat st;
    if (fstat(g_fd, &st) == 0 && st.st_size > LOG_MAX_BYTES) {   /* rotación */
        char vieja[PATH_LEN + 4];
        snprintf(vieja, sizeof vieja, "%s.1", g_ruta);
        close(g_fd);
        rename(g_ruta, vieja);
        if (abrir() != 0) return;
    }
    char ts[32], prog[1024], acc[512], pidtxt[96], linea[2048];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%S", &tm);
    escapar(programa, prog, sizeof prog);
    escapar(accion, acc, sizeof acc);
    if (pid > 0) snprintf(pidtxt, sizeof pidtxt, "%d", pid);
    else         snprintf(pidtxt, sizeof pidtxt, "\"%s\"", etiqueta ? etiqueta : "SISTEMA");
    int n = snprintf(linea, sizeof linea,
        "{\"timestamp\": \"%s\", \"pid\": %s, \"program\": \"%s\", "
        "\"files_touched\": %ld, \"score\": %d, \"action\": \"%s\"}\n",
        ts, pidtxt, prog, volumen, puntaje, acc);
    if (n > 0 && (size_t)n < sizeof linea && write(g_fd, linea, (size_t)n) < 0) { /* sin espacio */ }
}

void log_cerrar(void) { if (g_fd >= 0) close(g_fd); g_fd = -1; }
