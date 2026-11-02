#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Lee las líneas nuevas de /var/log/dpkg.log y registra instalaciones y
 * eliminaciones de paquetes. Formato: "AAAA-MM-DD HH:MM:SS accion paquete ...". */
void audit_dpkg_tick(void) {
    static long pos = -1;
    struct stat st;
    if (stat("/var/log/dpkg.log", &st) != 0) return;
    if (pos < 0 || st.st_size < pos) { pos = pos < 0 ? st.st_size : 0; if (pos == st.st_size) return; }
    if (st.st_size == pos) return;
    FILE *f = fopen("/var/log/dpkg.log", "r");
    if (!f) return;
    fseek(f, pos, SEEK_SET);
    char linea[1024];
    while (fgets(linea, sizeof linea, f)) {
        char accion[32], paquete[256], desc[400], etiqueta[64];
        if (sscanf(linea, "%*s %*s %31s %255s", accion, paquete) != 2) continue;
        if (strcmp(accion, "install") && strcmp(accion, "upgrade") &&
            strcmp(accion, "remove")  && strcmp(accion, "purge")) continue;
        snprintf(desc, sizeof desc, "Paquete %s: %s", accion, paquete);
        snprintf(etiqueta, sizeof etiqueta, "SISTEMA");
        log_alerta(0, etiqueta, desc, 1, 40, "SISTEMA / PAQUETE REGISTRADO (VERDE)");
    }
    pos = ftell(f);
    fclose(f);
}
