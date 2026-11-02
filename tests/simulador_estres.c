/* Simula el comportamiento de un ransomware sobre una carpeta de prueba.
 * Uso: ./simulador_estres <carpeta absoluta dentro de /tmp> [cantidad] [modo]
 *   renombrar    (por defecto) crea doc_NNNN.txt y lo renombra a doc_NNNN.txt.locked_test
 *   sobrescribir cifra EN SITIO los doc_NNNN.txt existentes (bytes aleatorios)
 *   borrar       crea doc_NNNN.dat cifrado y borra el doc_NNNN.txt original
 *
 * SEGURIDAD: el modo sobrescribir DESTRUYE archivos. Por eso solo acepta carpetas dentro de
 * /tmp/ (comprobado con realpath, así un enlace simbólico no puede apuntar a otro lado). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>

static int bajo_tmp(const char *r) { return !strncmp(r, "/tmp/", 5) && r[5] != '\0'; }

static int uso(const char *p) {
    fprintf(stderr, "uso: %s <carpeta absoluta dentro de /tmp> [cantidad] [renombrar|sobrescribir|borrar]\n"
                    "ejemplo: %s /tmp/zona_cuarentena_test 200 sobrescribir\n", p, p);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] != '/') {
        fprintf(stderr, "Error: falta la carpeta o no es una ruta absoluta (¿la variable $Z está vacía?).\n");
        return uso(argv[0]);
    }
    long n = 1000;
    if (argc > 2) {
        char *fin;
        n = strtol(argv[2], &fin, 10);
        if (*fin || n < 1 || n > 100000) { fprintf(stderr, "Error: la cantidad '%s' no es válida.\n", argv[2]); return uso(argv[0]); }
    }
    const char *modo = argc > 3 ? argv[3] : "renombrar";
    if (strcmp(modo, "renombrar") && strcmp(modo, "sobrescribir") && strcmp(modo, "borrar")) {
        fprintf(stderr, "Error: modo '%s' desconocido.\n", modo);
        return uso(argv[0]);
    }
    if (!bajo_tmp(argv[1])) {
        fprintf(stderr, "Error: por seguridad solo se permiten carpetas dentro de /tmp/ (recibí '%s').\n", argv[1]);
        return 1;
    }
    mkdir(argv[1], 0775);
    char dir[PATH_MAX];
    if (!realpath(argv[1], dir) || !bajo_tmp(dir)) {
        fprintf(stderr, "Error: la carpeta no existe o apunta fuera de /tmp/.\n");
        return 1;
    }
    printf("[Simulador C] pid %d: modo %s sobre %s (%ld archivos)\n", getpid(), modo, dir, n);
    fflush(stdout);
    char ruta[PATH_MAX + 32], otra[PATH_MAX + 64], datos[4096];
    for (long i = 0; i < n; i++) {
        snprintf(ruta, sizeof ruta, "%s/doc_%04ld.txt", dir, i);
        if (getrandom(datos, sizeof datos, 0) < 0) memset(datos, 'A' + i % 26, sizeof datos);
        if (!strcmp(modo, "sobrescribir")) {
            int fd = open(ruta, O_WRONLY | O_TRUNC | O_NOFOLLOW);
            if (fd < 0) continue;
            if (write(fd, datos, sizeof datos) < 0) perror("write");
            close(fd);
        } else if (!strcmp(modo, "borrar")) {
            char leido[4096];
            int orig = open(ruta, O_RDONLY | O_NOFOLLOW);   /* un ransomware real lee el original */
            if (orig >= 0) { if (read(orig, leido, sizeof leido) < 0) perror("read"); close(orig); }
            snprintf(otra, sizeof otra, "%s/doc_%04ld.dat", dir, i);
            int fd = open(otra, O_WRONLY | O_CREAT | O_TRUNC, 0664);
            if (fd < 0) continue;
            if (write(fd, datos, sizeof datos) < 0) perror("write");
            close(fd);
            unlink(ruta);
        } else {
            int fd = open(ruta, O_WRONLY | O_CREAT | O_TRUNC, 0664);
            if (fd < 0) { perror("open"); return 1; }
            memset(datos, 'A' + i % 26, 1024);
            if (write(fd, datos, 1024) < 0) perror("write");
            close(fd);
            snprintf(otra, sizeof otra, "%s.locked_test", ruta);
            rename(ruta, otra);
        }
        usleep(2000);
    }
    printf("[Simulador C] terminó sin ser detenido.\n");
    return 0;
}
