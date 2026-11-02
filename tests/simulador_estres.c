/* Simula el comportamiento de un ransomware sobre una carpeta de prueba.
 * Uso: ./simulador_estres <carpeta> [cantidad] [modo]
 *   renombrar   (por defecto) crea doc_NNNN.txt y lo renombra a doc_NNNN.txt.locked_test
 *   sobrescribir cifra EN SITIO los doc_NNNN.txt existentes (bytes aleatorios)
 *   borrar      crea doc_NNNN.dat cifrado y borra el doc_NNNN.txt original */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "uso: %s <carpeta> [cantidad] [modo]\n", argv[0]); return 1; }
    int n = argc > 2 ? atoi(argv[2]) : 1000;
    const char *modo = argc > 3 ? argv[3] : "renombrar";
    mkdir(argv[1], 0775);
    printf("[Simulador C] pid %d: modo %s sobre %s (%d archivos)\n", getpid(), modo, argv[1], n);
    fflush(stdout);
    char ruta[600], otra[640], datos[4096];
    for (int i = 0; i < n; i++) {
        snprintf(ruta, sizeof ruta, "%s/doc_%04d.txt", argv[1], i);
        if (getrandom(datos, sizeof datos, 0) < 0) memset(datos, 'A' + i % 26, sizeof datos);
        if (!strcmp(modo, "sobrescribir")) {
            int fd = open(ruta, O_WRONLY | O_TRUNC);
            if (fd < 0) continue;
            if (write(fd, datos, sizeof datos) < 0) perror("write");
            close(fd);
        } else if (!strcmp(modo, "borrar")) {
            char leido[4096];
            int orig = open(ruta, O_RDONLY);               /* un ransomware real lee el original */
            if (orig >= 0) { if (read(orig, leido, sizeof leido) < 0) perror("read"); close(orig); }
            snprintf(otra, sizeof otra, "%s/doc_%04d.dat", argv[1], i);
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
