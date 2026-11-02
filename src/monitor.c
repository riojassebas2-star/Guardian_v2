/* Monitor de archivos con DOS grupos fanotify:
 *   A (contenido): FAN_CLOSE_WRITE (con descriptor -> entropía, inodo) y
 *                  FAN_OPEN_PERM (permite copiar el original ANTES de que otro lo abra).
 *   B (nombres)  : FAN_CREATE / DELETE / MOVED_* con el nombre del archivo y el PID.
 * Los eventos de permiso se responden SIEMPRE (FAN_ALLOW): el guardián nunca niega accesos. */
#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <math.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/fanotify.h>

#define MAX_MARCAS 6000
#define MAX_PROF   8

static const config_t *C;
static int g_fa = -1, g_fb = -1, g_rescan, g_marcas, g_perm, g_desborde;

/* ---------------- marcas recursivas ---------------- */
static int saltar_dir(const char *n) {
    return !strcmp(n, "node_modules") || !strcmp(n, ".git") || !strcmp(n, ".cache");
}

static void marcar_dir(const char *d) {
    if (g_marcas >= MAX_MARCAS) return;
    unsigned long long a = FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD | (g_perm ? FAN_OPEN_PERM : 0);
    fanotify_mark(g_fa, FAN_MARK_ADD, a, AT_FDCWD, d);
    if (g_fb >= 0)
        fanotify_mark(g_fb, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ONDIR,
                      AT_FDCWD, d);
    g_marcas++;
}

static void marcar_arbol(const char *dir, int prof) {
    marcar_dir(dir);
    if (prof >= MAX_PROF) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR || !strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") || saltar_dir(e->d_name))
            continue;
        char sub[PATH_LEN];
        if (snprintf(sub, sizeof sub, "%s/%s", dir, e->d_name) >= (int)sizeof sub) continue;
        marcar_arbol(sub, prof + 1);
    }
    closedir(d);
}

void mon_marcar_todo(void) {
    g_marcas = 0;
    for (int i = 0; i < C->n_dirs; i++) marcar_arbol(C->watch_dirs[i], 0);
}

int mon_rescan_pendiente(void) { int r = g_rescan; g_rescan = 0; return r; }

int mon_iniciar(const config_t *c) {
    C = c;
    g_perm = c->boveda;
    g_fa = fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK | (g_perm ? FAN_CLASS_CONTENT : FAN_CLASS_NOTIF),
                         O_RDONLY | O_LARGEFILE);
    if (g_fa < 0) { perror("[Guardián] fanotify (grupo A)"); return -1; }
    g_fb = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_DFID_NAME,
                         O_RDONLY | O_LARGEFILE);
    if (g_fb < 0)
        fprintf(stderr, "[Guardián] Sin eventos de nombres (%s): no se verán renombrados ni borrados "
                        "(requiere kernel 5.9+).\n", strerror(errno));
    return 0;
}

int  mon_fd_a(void) { return g_fa; }
int  mon_fd_b(void) { return g_fb; }
void mon_cerrar(void) { if (g_fa >= 0) close(g_fa); if (g_fb >= 0) close(g_fb); }

/* ---------------- entropía y firmas de formato ---------------- */
static int tiene_firma(const unsigned char *b, size_t n) {
    static const struct { const char *m; size_t l, off; } F[] = {
        { "PK\x03\x04", 4, 0 }, { "\x1f\x8b", 2, 0 }, { "%PDF", 4, 0 }, { "\x89PNG", 4, 0 },
        { "\xff\xd8\xff", 3, 0 }, { "GIF8", 4, 0 }, { "7z\xbc\xaf", 4, 0 }, { "BZh", 3, 0 },
        { "\xfd" "7zXZ", 5, 0 }, { "Rar!", 4, 0 }, { "OggS", 4, 0 }, { "fLaC", 4, 0 },
        { "ID3", 3, 0 }, { "\x1a\x45\xdf\xa3", 4, 0 }, { "\x28\xb5\x2f\xfd", 4, 0 },
        { "ftyp", 4, 4 }, { "RIFF", 4, 0 }, { "SQLite format", 13, 0 }, { "wOFF", 4, 0 },
        { "wOF2", 4, 0 }, { "\x04\x22\x4d\x18", 4, 0 }, { "\xd0\xcf\x11\xe0", 4, 0 }, { NULL, 0, 0 } };
    if (n >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0) return 1;            /* MP3 */
    for (int i = 0; F[i].m; i++)
        if (n >= F[i].off + F[i].l && !memcmp(b + F[i].off, F[i].m, F[i].l)) return 1;
    return 0;
}

static int entropia_x100(const unsigned char *b, size_t n) {
    unsigned cuenta[256] = { 0 };
    for (size_t i = 0; i < n; i++) cuenta[b[i]]++;
    double h = 0;
    for (int i = 0; i < 256; i++)
        if (cuenta[i]) { double p = (double)cuenta[i] / (double)n; h -= p * log2(p); }
    return (int)(h * 100.0);
}

/* "Cifrado probable": contenido casi aleatorio Y sin cabecera de ningún formato conocido
 * (los .zip, .jpg, .pdf, .mp4... legítimos sí la tienen). */
static int es_cifrado(int fd) {
    unsigned char buf[4096];
    ssize_t n = pread(fd, buf, sizeof buf, 0);
    if (n < 512 || tiene_firma(buf, (size_t)n)) return 0;
    return entropia_x100(buf, (size_t)n) >= C->entropia_x100;
}

static void copiar_nombre(char *dst, const char *src, size_t n);
static int ignorado(int pid) { return pid <= 1 || pid == getpid() || hijo_es(pid); }

/* Los dos grupos son colas distintas del núcleo: si se leyera el CLOSE_WRITE de un archivo
 * antes que su CREATE, un archivo NUEVO parecería "preexistente" (falso positivo con tar,
 * git, descompresores...). Por eso los cierres se acumulan aquí y se procesan DESPUÉS de
 * leer el grupo B. Además, un archivo nacido hace pocos segundos (fecha de creación del
 * sistema de archivos) cuenta como nuevo aunque su evento CREATE no haya llegado. */
#define RECIENTE_SEG 10
#define MAX_CW 2048
typedef struct { int pid, cifrado, reciente, canario; uint64_t clave; char nombre[NOMBRE_MAX]; } cw_t;
static cw_t g_cw[MAX_CW];
static int  g_ncw;

void mon_vaciar_a(void) {
    for (int i = 0; i < g_ncw; i++) {
        const cw_t *e = &g_cw[i];
        if (e->canario) det_canario(e->pid, e->nombre, 0);
        else det_escritura(e->pid, e->clave, e->nombre, e->cifrado, e->reciente);
    }
    g_ncw = 0;
}

static int nacido_hace_poco(int fd) {
    struct statx sx;
    if (statx(fd, "", AT_EMPTY_PATH, STATX_BTIME, &sx) != 0 || !(sx.stx_mask & STATX_BTIME)) return 0;
    return sx.stx_btime.tv_sec >= (long long)time(NULL) - RECIENTE_SEG;
}

/* ---------------- grupo A ---------------- */
void mon_leer_a(void) {
    char buf[8192] __attribute__((aligned(8)));
    for (int vueltas = 0; vueltas < 64; vueltas++) {
        ssize_t len = read(g_fa, buf, sizeof buf);
        if (len <= 0) break;
        struct fanotify_event_metadata *m = (struct fanotify_event_metadata *)buf;
        for (; FAN_EVENT_OK(m, len); m = FAN_EVENT_NEXT(m, len)) {
            if (m->mask & FAN_Q_OVERFLOW) {
                if (!g_desborde++) log_alerta(0, "SISTEMA", "Cola de eventos desbordada (ráfaga enorme)", 0, 60,
                                              "ACTIVIDAD SOSPECHOSA (AMARILLO) [desborde]");
                continue;
            }
            if (m->fd < 0) continue;
            char enl[64], ruta[PATH_LEN];
            ruta[0] = '\0';
            snprintf(enl, sizeof enl, "/proc/self/fd/%d", m->fd);
            ssize_t l = readlink(enl, ruta, sizeof ruta - 1);
            if (l > 0) ruta[l] = '\0'; else l = 0;
            if (l > 10 && !strcmp(ruta + l - 10, " (deleted)")) ruta[l - 10] = '\0';
            const char *nombre = strrchr(ruta, '/');
            nombre = nombre ? nombre + 1 : ruta;
            int pid = m->pid;

            if (m->mask & FAN_OPEN_PERM) {
                if (!ignorado(pid) && !det_pid_confiable(pid)) bov_preimagen(m->fd, ruta, pid);
                struct fanotify_response r = { .fd = m->fd, .response = FAN_ALLOW };
                if (write(g_fa, &r, sizeof r) < 0) { /* el núcleo libera al cerrar el grupo */ }
            }
            if ((m->mask & FAN_CLOSE_WRITE) && !ignorado(pid) && *nombre) {
                struct stat st;
                int canario = canario_es(nombre);
                if ((canario || !det_pid_confiable(pid)) && fstat(m->fd, &st) == 0) {
                    if (g_ncw == MAX_CW) { mon_leer_b(); mon_vaciar_a(); }       /* búfer lleno */
                    cw_t *e = &g_cw[g_ncw++];
                    e->pid = pid; e->canario = canario;
                    e->clave = (uint64_t)st.st_ino ^ ((uint64_t)st.st_dev << 40);
                    copiar_nombre(e->nombre, nombre, sizeof e->nombre);
                    e->cifrado = !canario && S_ISREG(st.st_mode) ? es_cifrado(m->fd) : 0;
                    e->reciente = !canario && nacido_hace_poco(m->fd);
                }
            }
            close(m->fd);
        }
    }
}

/* ---------------- grupo B ---------------- */
/* En modo FID los eventos miden un número de bytes que NO es múltiplo de 8, así que el
 * siguiente evento queda desalineado: se lee todo con memcpy (seguro también en ARM). */
static void copiar_nombre(char *dst, const char *src, size_t n) {
    size_t l = strnlen(src, n - 1);
    memcpy(dst, src, l);
    dst[l] = '\0';
}

void mon_leer_b(void) {
    char buf[16384] __attribute__((aligned(8)));
    for (int vueltas = 0; vueltas < 64; vueltas++) {
        ssize_t len = read(g_fb, buf, sizeof buf);
        if (len <= 0) break;
        char *p = buf;
        while (len >= (ssize_t)sizeof(struct fanotify_event_metadata)) {
            struct fanotify_event_metadata m;
            memcpy(&m, p, sizeof m);
            if (m.event_len < m.metadata_len || m.event_len > (unsigned)len) break;
            char *info = p + m.metadata_len, *fin = p + m.event_len;
            char nombre[NOMBRE_MAX] = "";
            while (info + sizeof(struct fanotify_event_info_header) <= fin) {
                struct fanotify_event_info_header h;
                memcpy(&h, info, sizeof h);
                if (h.len < sizeof h || info + h.len > fin) break;
                if (h.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                    /* cabecera + fsid + file_handle{handle_bytes, handle_type, f_handle[]} + nombre */
                    size_t off_fh = offsetof(struct fanotify_event_info_fid, handle);
                    unsigned hb = 0;
                    if (off_fh + sizeof hb <= h.len) {
                        memcpy(&hb, info + off_fh, sizeof hb);
                        size_t off_nombre = off_fh + 8 + hb;
                        if (off_nombre < h.len)
                            copiar_nombre(nombre, info + off_nombre, h.len - off_nombre < NOMBRE_MAX ? h.len - off_nombre : NOMBRE_MAX);
                    }
                }
                info += h.len;
            }
            if (m.fd >= 0) close(m.fd);
            if (!(m.mask & FAN_Q_OVERFLOW) && nombre[0] && !ignorado(m.pid)) {
                if (m.mask & FAN_ONDIR) {                    /* carpeta nueva: marcarla pronto */
                    if (m.mask & (FAN_CREATE | FAN_MOVED_TO)) g_rescan = 1;
                } else {
                    int pid = m.pid, can = canario_es(nombre);
                    if ((m.mask & FAN_CREATE) && !can)   det_creacion(pid, nombre);
                    if (m.mask & FAN_MOVED_FROM)         { if (can) det_canario(pid, nombre, 0); else det_mov_desde(pid, nombre); }
                    if ((m.mask & FAN_MOVED_TO) && !can) det_mov_hacia(pid, nombre);
                    if (m.mask & FAN_DELETE)             { if (can) det_canario(pid, nombre, 1); else det_borrado(pid, nombre); }
                }
            }
            p += m.event_len;
            len -= (ssize_t)m.event_len;
        }
    }
}
