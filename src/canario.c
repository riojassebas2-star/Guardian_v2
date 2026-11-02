/* Archivos señuelo ("canarios"). Se crean en las carpetas protegidas con nombres que un
 * ransomware encuentra primero (0000_...) y último (zzzz_...). Ningún usuario ni programa
 * legítimo los modifica: escribir o renombrar uno equivale a detección inmediata. */
#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

static const char *NOMBRES[] = { "0000_documento_respaldo.docx", "0000_contrasenas_banco.txt",
                                 "zzzz_informe_financiero.xlsx", "zzzz_cuentas_2026.csv", NULL };
static int g_dirs;

int canario_es(const char *nombre) {
    for (int i = 0; NOMBRES[i]; i++) if (!strcmp(nombre, NOMBRES[i])) return 1;
    return 0;
}

static void crear_en(const char *dir) {
    struct stat sd;
    if (stat(dir, &sd) != 0 || !S_ISDIR(sd.st_mode)) return;
    char ruta[PATH_LEN + 64];
    for (int i = 0; NOMBRES[i]; i++) {
        snprintf(ruta, sizeof ruta, "%s/%s", dir, NOMBRES[i]);
        int fd = open(ruta, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (fd < 0) continue;                                /* ya existe, o no hay permiso */
        char txt[2048];
        int n = snprintf(txt, sizeof txt, "GUARDIAN-CANARIO: archivo señuelo, no lo modifiques.\n");
        for (int k = 0; k < 40 && n < (int)sizeof txt - 64; k++)
            n += snprintf(txt + n, sizeof txt - (size_t)n, "%04d;registro-interno;saldo;%d.%02d\n", k, 1000 + k * 37, k % 100);
        if (write(fd, txt, (size_t)n) < 0) { /* no crítico */ }
        if (fchown(fd, sd.st_uid, sd.st_gid) != 0) { /* no crítico */ }
        close(fd);
    }
}

static void recorrer(const config_t *c, const char *dir, int prof) {
    if (g_dirs++ > 200) return;
    crear_en(dir);
    if (prof >= c->canarios_prof) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_type != DT_DIR || e->d_name[0] == '.' || !strcmp(e->d_name, "node_modules")) continue;
        char sub[PATH_LEN];
        if (snprintf(sub, sizeof sub, "%s/%s", dir, e->d_name) >= (int)sizeof sub) continue;
        recorrer(c, sub, prof + 1);
    }
    closedir(d);
}

void canarios_asegurar(const config_t *c) {
    if (!c->canarios) return;
    g_dirs = 0;
    for (int i = 0; i < c->n_dirs; i++) recorrer(c, c->watch_dirs[i], 0);
}

/* En marcha se hace desde un proceso hijo: así el bucle principal nunca se bloquea y
 * sus eventos (hijo_registrar) se ignoran. */
void canarios_asegurar_async(const config_t *c) {
    if (!c->canarios) return;
    pid_t p = fork();
    if (p < 0) return;
    if (p == 0) { canarios_asegurar(c); _exit(0); }
    hijo_registrar(p);
}
