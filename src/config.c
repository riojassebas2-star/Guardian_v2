#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>

static char *recortar(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *f = s + strlen(s);
    while (f > s && isspace((unsigned char)f[-1])) *--f = '\0';
    return s;
}

/* Dónde viven la configuración y los datos:
 *  - GUARDIAN_HOME (pruebas) o carpeta del ejecutable con config/ (desarrollo)
 *  - /etc/guardian (instalado como servicio: modo "sistema", exige root:root) */
void config_ubicar(char *home, size_t nh, char *conf_dir, size_t nc, int *sistema) {
    char exe[PATH_MAX], t[PATH_MAX + 32];
    *sistema = 0;
    const char *env = getenv("GUARDIAN_HOME");
    if (env && *env) {
        snprintf(home, nh, "%s", env);
        snprintf(conf_dir, nc, "%s/config", home);
        return;
    }
    ssize_t l = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (l <= 0) l = 0;
    exe[l] = '\0';
    char *b = strrchr(exe, '/');
    if (b) *b = '\0';
    snprintf(t, sizeof t, "%s/config/guardian.conf", exe);
    if (access(t, R_OK) == 0) {
        snprintf(home, nh, "%s", exe);
        snprintf(conf_dir, nc, "%s/config", exe);
    } else if (access("/etc/guardian/guardian.conf", R_OK) == 0) {
        snprintf(home, nh, "/etc/guardian");
        snprintf(conf_dir, nc, "/etc/guardian");
        *sistema = 1;
    } else {
        snprintf(home, nh, "%s", exe);
        snprintf(conf_dir, nc, "%s/config", exe);
    }
}

static void resolver_ruta(const config_t *c, const char *v, char *out, size_t n) {
    int r;
    if (v[0] == '~') {
        struct passwd *pw = getpwuid(c->owner_uid);
        r = snprintf(out, n, "%s%s", pw ? pw->pw_dir : "", v + 1);
    } else if (v[0] == '/') {
        r = snprintf(out, n, "%s", v);
    } else {
        r = snprintf(out, n, "%s/%s", c->home, v);
    }
    if (r < 0 || (size_t)r >= n) { out[0] = '\0'; return; }
    size_t l = strlen(out);
    while (l > 1 && out[l - 1] == '/') out[--l] = '\0';
}

static void cargar_whitelist(config_t *c) {
    struct stat st;
    c->n_wl = 0;
    FILE *f = fopen(c->whitelist_file, "r");
    if (!f) return;
    if (fstat(fileno(f), &st) == 0) c->wl_mtime = (long)st.st_mtime;
    char linea[512];
    while (fgets(linea, sizeof linea, f) && c->n_wl < MAX_WL) {
        char *s = recortar(linea);
        if (*s == '\0' || *s == '#') continue;
        wl_t *w = &c->whitelist[c->n_wl];
        memset(w, 0, sizeof *w);
        char nombre[NOMBRE_WL], extra[100] = "";
        if (sscanf(s, "%127s %99s", nombre, extra) < 1) continue;
        snprintf(w->nombre, sizeof w->nombre, "%s", nombre);
        if (!strncmp(extra, "sha256=", 7) && strlen(extra + 7) == 64) {
            for (int i = 0; i < 64; i++) w->sha[i] = (char)tolower((unsigned char)extra[7 + i]);
            w->sha[64] = '\0';
        }
        c->n_wl++;
    }
    fclose(f);
}

int config_whitelist_refrescar(config_t *c) {
    struct stat st;
    if (stat(c->whitelist_file, &st) == 0 && (long)st.st_mtime != c->wl_mtime) {
        cargar_whitelist(c);
        return 1;
    }
    return 0;
}

static void aplicar_clave(config_t *c, const char *k, const char *v) {
    if (!strcmp(k, "watch_dir")) {
        if (c->n_dirs < MAX_DIRS) {
            resolver_ruta(c, v, c->watch_dirs[c->n_dirs], PATH_LEN);
            if (c->watch_dirs[c->n_dirs][0]) c->n_dirs++;
        }
    }
    else if (!strcmp(k, "log_file"))         resolver_ruta(c, v, c->log_file, PATH_LEN);
    else if (!strcmp(k, "pid_file"))         resolver_ruta(c, v, c->pid_file, PATH_LEN);
    else if (!strcmp(k, "socket"))           resolver_ruta(c, v, c->sock_file, PATH_LEN);
    else if (!strcmp(k, "boveda_dir"))       resolver_ruta(c, v, c->vault_dir, PATH_LEN);
    else if (!strcmp(k, "umbral_eventos"))   c->umbral_eventos = atoi(v);
    else if (!strcmp(k, "umbral_archivos"))  c->umbral_archivos = atoi(v);
    else if (!strcmp(k, "ventana_seg"))      c->ventana_seg = atoi(v);
    else if (!strcmp(k, "umbral_critico"))   c->umbral_critico = atoi(v);
    else if (!strcmp(k, "entropia"))         c->entropia_x100 = (int)(atof(v) * 100.0);
    else if (!strcmp(k, "accion"))
        c->accion = !strcmp(v, "terminar") ? ACC_TERMINAR : !strcmp(v, "alerta") ? ACC_ALERTA : ACC_CONGELAR;
    else if (!strcmp(k, "canarios"))         c->canarios = atoi(v);
    else if (!strcmp(k, "canarios_prof"))    c->canarios_prof = atoi(v);
    else if (!strcmp(k, "boveda"))           c->boveda = atoi(v);
    else if (!strcmp(k, "boveda_max_archivo_mb")) c->boveda_max_archivo = atol(v) * 1024L * 1024L;
    else if (!strcmp(k, "boveda_max_total_mb"))   c->boveda_max_total = atol(v) * 1024L * 1024L;
    else if (!strcmp(k, "boveda_ttl_min"))   c->boveda_ttl_min = atoi(v);
    else if (!strcmp(k, "notificar"))        c->notificar = atoi(v);
    else if (!strcmp(k, "net_activo"))       c->net_activo = atoi(v);
    else if (!strcmp(k, "net_modo"))         c->net_bloquear = !strcmp(v, "bloquear");
    else if (!strcmp(k, "net_umbral_bytes")) c->net_umbral_bytes = atol(v);
    else if (!strcmp(k, "net_ventana_seg"))  c->net_ventana_seg = atoi(v);
    else if (!strcmp(k, "audit_dpkg"))       c->audit_dpkg = atoi(v);
}

/* Dos pasadas: la 0 solo lee "usuario" (necesario para expandir "~"). */
static void leer_conf(config_t *c, const char *ruta, int fase) {
    FILE *f = fopen(ruta, "r");
    if (!f) { if (fase == 1) fprintf(stderr, "[Guardián] Sin %s: valores por defecto.\n", ruta); return; }
    char linea[1024];
    while (fgets(linea, sizeof linea, f)) {
        char *s = recortar(linea);
        if (*s == '\0' || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = recortar(s), *v = recortar(eq + 1);
        char *hash = strchr(v, '#');                  /* comentario al final de línea */
        if (hash) { *hash = '\0'; v = recortar(v); }
        if (fase == 0) {
            if (!strcmp(k, "usuario")) {
                struct passwd *pw = getpwnam(v);
                if (pw) { c->owner_uid = pw->pw_uid; c->owner_gid = pw->pw_gid; }
                else fprintf(stderr, "[Guardián] Usuario '%s' no existe.\n", v);
            }
        } else if (strcmp(k, "usuario")) aplicar_clave(c, k, v);
    }
    fclose(f);
}

int config_cargar(config_t *c, const char *home, const char *conf_dir, int sistema) {
    struct stat st;
    memset(c, 0, sizeof *c);
    snprintf(c->home, sizeof c->home, "%s", home);
    snprintf(c->conf_dir, sizeof c->conf_dir, "%s", conf_dir);
    c->sistema = sistema;
    if (stat(home, &st) != 0) { perror("home"); return -1; }
    c->owner_uid = sistema ? 0 : st.st_uid;
    c->owner_gid = sistema ? 0 : st.st_gid;

    c->umbral_eventos = 50;  c->umbral_archivos = 20;
    c->ventana_seg = 5;      c->umbral_critico = 90;
    c->entropia_x100 = 720;  c->accion = ACC_CONGELAR;
    c->canarios = 1;         c->canarios_prof = 1;
    c->boveda = 1;
    c->boveda_max_archivo = 16L * 1024 * 1024;
    c->boveda_max_total = 512L * 1024 * 1024;
    c->boveda_ttl_min = 120;
    c->notificar = 1;
    c->net_activo = 1;       c->net_bloquear = 0;
    c->net_umbral_bytes = 5L * 1024 * 1024;  c->net_ventana_seg = 5;
    c->audit_dpkg = 1;
    snprintf(c->log_file, sizeof c->log_file, "%s/logs/guardian_alertas.jsonl", home);
    snprintf(c->pid_file, sizeof c->pid_file, "%s/logs/guardian.pid", home);
    snprintf(c->sock_file, sizeof c->sock_file, "%s/logs/control.sock", home);
    snprintf(c->vault_dir, sizeof c->vault_dir, "%s/boveda", home);
    snprintf(c->whitelist_file, sizeof c->whitelist_file, "%s/whitelist.txt", conf_dir);

    char ruta[PATH_LEN + 32];
    snprintf(ruta, sizeof ruta, "%s/guardian.conf", conf_dir);
    leer_conf(c, ruta, 0);
    leer_conf(c, ruta, 1);

    if (c->umbral_eventos < 1) c->umbral_eventos = 1;
    if (c->umbral_archivos < 1) c->umbral_archivos = 1;
    if (c->umbral_archivos > MAX_INODOS) c->umbral_archivos = MAX_INODOS;
    if (c->ventana_seg < 1) c->ventana_seg = 1;
    if (c->net_ventana_seg < 1) c->net_ventana_seg = 1;
    if (c->umbral_critico < 1 || c->umbral_critico > 100) c->umbral_critico = 90;
    if (c->entropia_x100 < 500 || c->entropia_x100 > 800) c->entropia_x100 = 720;
    if (c->canarios_prof < 0) c->canarios_prof = 0;
    if (c->canarios_prof > 3) c->canarios_prof = 3;
    if (c->boveda_ttl_min < 1) c->boveda_ttl_min = 1;
    if (c->n_dirs == 0)
        snprintf(c->watch_dirs[c->n_dirs++], PATH_LEN, "/tmp/zona_cuarentena_test");

    cargar_whitelist(c);
    return 0;
}

static int inseguro(const char *ruta) {
    struct stat st;
    if (stat(ruta, &st) != 0) return 0;               /* no existe: no hay riesgo */
    if (st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        fprintf(stderr, "[Guardián] %s no es root:root o es escribible por otros.\n", ruta);
        return 1;
    }
    return 0;
}

/* En modo sistema la configuración debe ser de root: si no, cualquier usuario
 * podría agregar su malware a la lista blanca. */
int config_permisos(const config_t *c) {
    char r[PATH_LEN + 32];
    int n = inseguro(c->conf_dir);
    snprintf(r, sizeof r, "%s/guardian.conf", c->conf_dir); n += inseguro(r);
    n += inseguro(c->whitelist_file);
    return n;
}

int ruta_bajo_dirs(const config_t *c, const char *ruta) {
    for (int i = 0; i < c->n_dirs; i++) {
        size_t l = strlen(c->watch_dirs[i]);
        if (!strncmp(ruta, c->watch_dirs[i], l) && (ruta[l] == '/' || ruta[l] == '\0')) return 1;
    }
    return 0;
}

/* Un proceso es "confiable" si su ejecutable coincide con la lista blanca:
 *  - ruta absoluta: coincidencia exacta; nombre simple: nombre exacto Y ruta de sistema;
 *  - si la entrada trae sha256=..., el binario en disco debe tener ese hash;
 *  - un ejecutable borrado del disco nunca es confiable. */
int wl_confiable(const config_t *c, const char *exe) {
    static const char *prefijos[] = { "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", NULL };
    size_t l = strlen(exe);
    if (l >= 10 && !strcmp(exe + l - 10, " (deleted)")) return 0;
    const char *base = strrchr(exe, '/');
    base = base ? base + 1 : exe;
    for (int i = 0; i < c->n_wl; i++) {
        const wl_t *w = &c->whitelist[i];
        int coincide = 0;
        if (w->nombre[0] == '/') coincide = !strcmp(exe, w->nombre);
        else if (!strcmp(base, w->nombre))
            for (int p = 0; prefijos[p]; p++)
                if (!strncmp(exe, prefijos[p], strlen(prefijos[p]))) { coincide = 1; break; }
        if (!coincide) continue;
        if (w->sha[0]) {
            char h[65];
            if (sha256_archivo(exe, h) != 0 || strcmp(h, w->sha) != 0) continue;
        }
        return 1;
    }
    return 0;
}
