/* Bóveda de recuperación: copia previa de archivos.
 *
 * Cuando un proceso NO confiable abre un archivo de una carpeta protegida, el monitor
 * (evento FAN_OPEN_PERM) detiene esa apertura un instante y aquí se guarda una copia del
 * original. Si luego el archivo es cifrado, se puede restaurar:  guardian --restaurar.
 *
 *   <boveda>/obj/<seq>.bak   copias (root, 0600)
 *   <boveda>/indice.tsv      índice append-only:  A<TAB>seq...ruta  |  D<TAB>seq (borrada)
 * La bóveda es de root (0700): un ransomware que corre como usuario no puede borrarla. */
#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct {
    unsigned long seq; time_t epoch; int pid; long size; uint64_t clave;
    mode_t mode; uid_t uid; gid_t gid; long long mtime_ns; char *ruta; int vivo;
} ent_t;

static const config_t *C;
static ent_t  *E;
static size_t  nE, capE, cabeza;          /* cabeza: primer índice posiblemente vivo */
static unsigned long g_seq;
static long    g_total, g_vivas;
static int     g_idx = -1;
static char    g_idxruta[PATH_LEN + 32];

/* ---------- codificación de rutas (sin tabuladores ni saltos de línea) ---------- */
static void codificar(const char *s, char *o, size_t n) {
    size_t j = 0;
    for (; *s && j + 4 < n; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '%' || c == '\t' || c == '\n' || c == '\r') j += (size_t)snprintf(o + j, n - j, "%%%02X", c);
        else o[j++] = (char)c;
    }
    o[j] = '\0';
}

static void decodificar(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%' && isxdigit((unsigned char)r[1]) && isxdigit((unsigned char)r[2])) {
            char h[3] = { r[1], r[2], 0 };
            *w++ = (char)strtol(h, NULL, 16);
            r += 3;
        } else *w++ = *r++;
    }
    *w = '\0';
}

/* ---------- índice en memoria ---------- */
static ent_t *anadir(void) {
    if (nE == capE) {
        capE = capE ? capE * 2 : 1024;
        E = realloc(E, capE * sizeof *E);
        if (!E) { perror("realloc"); exit(1); }
    }
    memset(&E[nE], 0, sizeof E[nE]);
    return &E[nE++];
}

static void objeto_ruta(unsigned long seq, char *out, size_t n) {
    snprintf(out, n, "%s/obj/%010lu.bak", C->vault_dir, seq);
}

static void apend(const char *linea, size_t n) {
    if (g_idx >= 0 && write(g_idx, linea, n) < 0) { /* sin espacio: se pierde el registro */ }
}

static void evictar(size_t i) {
    if (!E[i].vivo) return;
    char obj[PATH_LEN + 40], d[64];
    objeto_ruta(E[i].seq, obj, sizeof obj);
    unlink(obj);
    int n = snprintf(d, sizeof d, "D\t%lu\n", E[i].seq);
    apend(d, (size_t)n);
    g_total -= E[i].size; g_vivas--;
    E[i].vivo = 0;
    free(E[i].ruta); E[i].ruta = NULL;
}

static void cargar_indice(void) {
    FILE *f = fopen(g_idxruta, "r");
    if (!f) return;
    static char linea[PATH_LEN * 3 + 256];
    while (fgets(linea, sizeof linea, f)) {
        char *campo[11];
        int k = 0;
        campo[k++] = linea;
        for (char *p = linea; *p && k < 11; p++)
            if (*p == '\t') { *p = '\0'; campo[k++] = p + 1; }
        campo[k - 1][strcspn(campo[k - 1], "\n")] = '\0';
        if (campo[0][0] == 'A' && k == 11) {
            ent_t *e = anadir();
            e->seq = strtoul(campo[1], NULL, 10);
            e->epoch = (time_t)atoll(campo[2]);
            e->pid = atoi(campo[3]);
            e->size = atol(campo[4]);
            e->mtime_ns = atoll(campo[5]);
            e->clave = strtoull(campo[6], NULL, 10);
            e->mode = (mode_t)strtoul(campo[7], NULL, 10);
            e->uid = (uid_t)strtoul(campo[8], NULL, 10);
            e->gid = (gid_t)strtoul(campo[9], NULL, 10);
            decodificar(campo[10]);
            e->ruta = strdup(campo[10]);
            e->vivo = 1;
            if (e->seq > g_seq) g_seq = e->seq;
            g_total += e->size; g_vivas++;
        } else if (campo[0][0] == 'D' && k >= 2) {
            unsigned long s = strtoul(campo[1], NULL, 10);
            for (size_t i = nE; i-- > 0; )
                if (E[i].vivo && E[i].seq == s) {
                    E[i].vivo = 0; g_total -= E[i].size; g_vivas--;
                    free(E[i].ruta); E[i].ruta = NULL;
                    break;
                }
        }
    }
    fclose(f);
    while (cabeza < nE && !E[cabeza].vivo) cabeza++;
}

static void ruta_vault(const config_t *c) {
    C = c;
    snprintf(g_idxruta, sizeof g_idxruta, "%s/indice.tsv", c->vault_dir);
}

/* Reescribe el índice sin entradas borradas (al arrancar, si hay mucha basura). */
static void compactar_indice(void) {
    char tmp[PATH_LEN + 48];
    snprintf(tmp, sizeof tmp, "%s.nuevo", g_idxruta);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (size_t i = 0; i < nE; i++) {
        if (!E[i].vivo) continue;
        char r[PATH_LEN * 3];
        codificar(E[i].ruta, r, sizeof r);
        fprintf(f, "A\t%lu\t%lld\t%d\t%ld\t%lld\t%llu\t%u\t%u\t%u\t%s\n", E[i].seq, (long long)E[i].epoch,
                E[i].pid, E[i].size, E[i].mtime_ns, (unsigned long long)E[i].clave,
                (unsigned)E[i].mode, (unsigned)E[i].uid, (unsigned)E[i].gid, r);
    }
    fclose(f);
    chmod(tmp, 0600);
    rename(tmp, g_idxruta);
}

int bov_iniciar(const config_t *c) {
    if (!c->boveda) return 0;
    ruta_vault(c);
    char obj[PATH_LEN + 8];
    snprintf(obj, sizeof obj, "%s/obj", c->vault_dir);
    mkdir(c->vault_dir, 0700);
    mkdir(obj, 0700);
    chmod(c->vault_dir, 0700);
    cargar_indice();
    size_t muertas = nE - (size_t)g_vivas;
    if (muertas > 500 && muertas > (size_t)g_vivas) {
        compactar_indice();
        for (size_t i = 0, j = 0; i < nE; i++) if (E[i].vivo) E[j++] = E[i];
        nE = (size_t)g_vivas; cabeza = 0;
    }
    g_idx = open(g_idxruta, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (g_idx < 0) { perror("[Guardián] No se pudo abrir el índice de la bóveda"); return -1; }
    return 0;
}

static void hacer_espacio(long necesario) {
    while (g_total + necesario > C->boveda_max_total && cabeza < nE) {
        evictar(cabeza);
        while (cabeza < nE && !E[cabeza].vivo) cabeza++;
    }
}

void bov_preimagen(int fd, const char *ruta, int pid) {
    if (!C || !C->boveda || g_idx < 0) return;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > C->boveda_max_archivo)
        return;
    const char *nombre = strrchr(ruta, '/');
    nombre = nombre ? nombre + 1 : ruta;
    if (canario_es(nombre)) return;

    long long t = mono_seg();
    pidstat_t *ps = pt_obtener(pid, t);
    pt_ventana(ps, t, C->ventana_seg);
    if (++ps->vault_n > 400) return;           /* un proceso que abre cientos de archivos: no inundar */

    long long mt = (long long)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
    uint64_t clave = (uint64_t)st.st_ino ^ ((uint64_t)st.st_dev << 32) ^
                     ((uint64_t)mt * 0x9E3779B97F4A7C15ULL) ^ ((uint64_t)st.st_size * 31u) ^
                     ((uint64_t)pid * 0xD6E8FEB86659FD93ULL);
    size_t visto = 0;
    for (size_t i = nE; i-- > cabeza && visto < 4096; visto++)
        if (E[i].vivo && E[i].clave == clave) return;                      /* ya está respaldada */

    hacer_espacio(st.st_size);
    if (g_total + st.st_size > C->boveda_max_total) return;

    unsigned long seq = ++g_seq;
    char obj[PATH_LEN + 40];
    objeto_ruta(seq, obj, sizeof obj);
    int out = open(obj, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0) return;
    static char buf[65536];
    off_t off = 0;
    int ok = 1;
    while (off < st.st_size) {
        size_t quiero = (size_t)(st.st_size - off) < sizeof buf ? (size_t)(st.st_size - off) : sizeof buf;
        ssize_t r = pread(fd, buf, quiero, off);
        if (r <= 0 || write(out, buf, (size_t)r) != r) { ok = 0; break; }
        off += r;
    }
    close(out);
    if (!ok) { unlink(obj); return; }

    ent_t *e = anadir();
    e->seq = seq; e->epoch = time(NULL); e->pid = pid; e->size = (long)st.st_size;
    e->clave = clave; e->mode = st.st_mode & 07777; e->uid = st.st_uid; e->gid = st.st_gid;
    e->mtime_ns = mt; e->ruta = strdup(ruta); e->vivo = 1;
    g_total += e->size; g_vivas++;
    char r[PATH_LEN * 3], linea[PATH_LEN * 3 + 200];
    codificar(ruta, r, sizeof r);
    int n = snprintf(linea, sizeof linea, "A\t%lu\t%lld\t%d\t%ld\t%lld\t%llu\t%u\t%u\t%u\t%s\n",
                     seq, (long long)e->epoch, pid, e->size, mt, (unsigned long long)clave,
                     (unsigned)e->mode, (unsigned)e->uid, (unsigned)e->gid, r);
    apend(linea, (size_t)n);
}

/* Caducidad: las copias más viejas que el TTL se eliminan. */
void bov_tick(long long ahora) {
    static long long ultimo;
    if (!C || !C->boveda || ahora - ultimo < 10) return;
    ultimo = ahora;
    time_t limite = time(NULL) - (time_t)C->boveda_ttl_min * 60;
    while (cabeza < nE && (!E[cabeza].vivo || E[cabeza].epoch < limite)) {
        evictar(cabeza);
        cabeza++;
    }
    if (cabeza > 4096) {                                  /* compactar el arreglo en memoria */
        memmove(E, E + cabeza, (nE - cabeza) * sizeof *E);
        nE -= cabeza; cabeza = 0;
    }
}

void bov_texto(char *out, size_t n) {
    if (!C || !C->boveda) { snprintf(out, n, "Bóveda: desactivada\n"); return; }
    snprintf(out, n, "Bóveda: %ld copias, %.1f MB de %.0f MB (caducan a los %d min)\n",
             g_vivas, (double)g_total / 1048576.0, (double)C->boveda_max_total / 1048576.0, C->boveda_ttl_min);
}

/* ---------------- línea de comandos: --restaurar / --boveda ---------------- */
static int mismo_contenido(const char *a, const char *b) {
    int fa = open(a, O_RDONLY | O_NOFOLLOW), fb = open(b, O_RDONLY);
    int igual = 0;
    if (fa >= 0 && fb >= 0) {
        static char x[65536], y[65536];
        igual = 1;
        for (;;) {
            ssize_t rx = read(fa, x, sizeof x), ry = read(fb, y, sizeof y);
            if (rx != ry || (rx > 0 && memcmp(x, y, (size_t)rx) != 0)) { igual = 0; break; }
            if (rx <= 0) break;
        }
    }
    if (fa >= 0) close(fa);
    if (fb >= 0) close(fb);
    return igual;
}

static int restaurar_uno(const ent_t *e, const char *obj) {
    char tmp[PATH_LEN + 40];
    snprintf(tmp, sizeof tmp, "%s.guardian-restore", e->ruta);
    int in = open(obj, O_RDONLY), out = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (in < 0 || out < 0) { if (in >= 0) close(in); if (out >= 0) close(out); return -1; }
    static char buf[65536];
    ssize_t r;
    int ok = 1;
    while ((r = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, (size_t)r) != r) { ok = 0; break; }
    if (r < 0) ok = 0;
    struct timespec ts[2] = { { 0, UTIME_OMIT }, { (time_t)(e->mtime_ns / 1000000000LL), (long)(e->mtime_ns % 1000000000LL) } };
    if (ok) { fchmod(out, e->mode); if (fchown(out, e->uid, e->gid) != 0) { /* no crítico */ } futimens(out, ts); }
    close(in); close(out);
    if (!ok || rename(tmp, e->ruta) != 0) { unlink(tmp); return -1; }
    return 0;
}

int bov_restaurar_cli(const config_t *c, int pid, int minutos, int simular) {
    ruta_vault(c);
    if (!c->boveda) { fprintf(stderr, "La bóveda está desactivada en la configuración.\n"); return 1; }
    if (access(c->vault_dir, R_OK | X_OK) != 0) {
        fprintf(stderr, "No se puede leer la bóveda (%s): ejecuta con sudo.\n", c->vault_dir);
        return 1;
    }
    cargar_indice();
    time_t corte = minutos > 0 ? time(NULL) - (time_t)minutos * 60 : 0;
    int restaurados = 0, iguales = 0, errores = 0, candidatas = 0;
    for (size_t i = 0; i < nE; i++) {
        const ent_t *e = &E[i];
        if (!e->vivo || e->epoch < corte || (pid > 0 && e->pid != pid)) continue;
        int repetida = 0;                      /* por archivo se usa la copia MÁS ANTIGUA del criterio */
        for (size_t j = 0; j < i && !repetida; j++)
            if (E[j].vivo && E[j].epoch >= corte && (pid <= 0 || E[j].pid == pid) && !strcmp(E[j].ruta, e->ruta))
                repetida = 1;
        if (repetida) continue;
        candidatas++;
        char obj[PATH_LEN + 40];
        objeto_ruta(e->seq, obj, sizeof obj);
        if (mismo_contenido(e->ruta, obj)) { iguales++; continue; }
        if (simular) { printf("SE RESTAURARÍA  %s\n", e->ruta); restaurados++; continue; }
        if (restaurar_uno(e, obj) == 0) { printf("RESTAURADO      %s\n", e->ruta); restaurados++; }
        else { printf("ERROR           %s (¿la carpeta ya no existe?)\n", e->ruta); errores++; }
    }
    printf("\n%s: %d archivo(s)%s, %d sin cambios, %d con error (de %d candidatos).\n",
           simular ? "Simulación" : "Resultado", restaurados, simular ? " por restaurar" : " restaurado(s)",
           iguales, errores, candidatas);
    return errores ? 2 : 0;
}

int bov_estado_cli(const config_t *c) {
    ruta_vault(c);
    if (access(c->vault_dir, R_OK | X_OK) != 0) { fprintf(stderr, "Ejecuta con sudo.\n"); return 1; }
    cargar_indice();
    char t[200];
    bov_texto(t, sizeof t);
    fputs(t, stdout);
    return 0;
}
