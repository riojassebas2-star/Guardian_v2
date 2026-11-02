/* Canal de control: socket UNIX con permisos 0600 (solo root) + cliente de línea de comandos.
 * Comandos: estado | liberar <pid> | terminar <pid> */
#define _GNU_SOURCE
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

static int ruta_sock(const config_t *c, struct sockaddr_un *a) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    if (strlen(c->sock_file) >= sizeof a->sun_path) return -1;
    strcpy(a->sun_path, c->sock_file);
    return 0;
}

int ctl_iniciar(const config_t *c) {
    struct sockaddr_un a;
    if (ruta_sock(c, &a) != 0) { fprintf(stderr, "[Guardián] Ruta de socket demasiado larga.\n"); return -1; }
    char dir[sizeof a.sun_path];                         /* la carpeta del socket, solo para root */
    snprintf(dir, sizeof dir, "%s", a.sun_path);
    char *barra = strrchr(dir, '/');
    if (barra && barra != dir) { *barra = '\0'; mkdir(dir, 0700); }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    unlink(a.sun_path);
    mode_t viejo = umask(0177);
    int r = bind(fd, (struct sockaddr *)&a, sizeof a);
    umask(viejo);
    if (r != 0 || listen(fd, 4) != 0) { perror("[Guardián] Socket de control"); close(fd); return -1; }
    chmod(a.sun_path, 0600);
    return fd;
}

void ctl_atender(int fd) {
    int cl = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (cl < 0) return;
    struct ucred cred;
    socklen_t cl_len = sizeof cred;
    char cmd[128] = "", resp[4096] = "";
    if (getsockopt(cl, SOL_SOCKET, SO_PEERCRED, &cred, &cl_len) != 0 || cred.uid != 0) {
        snprintf(resp, sizeof resp, "Acceso denegado: solo root.\n");
    } else {
        struct pollfd p = { cl, POLLIN, 0 };
        if (poll(&p, 1, 100) > 0) {
            ssize_t n = read(cl, cmd, sizeof cmd - 1);
            cmd[n > 0 ? n : 0] = '\0';
            cmd[strcspn(cmd, "\r\n")] = '\0';
        }
        int pid = 0;
        if (!strcmp(cmd, "estado")) {
            det_estado(resp, sizeof resp);
            size_t l = strlen(resp);
            bov_texto(resp + l, sizeof resp - l);
        } else if (sscanf(cmd, "liberar %d", &pid) == 1) det_liberar(pid, resp, sizeof resp);
        else if (sscanf(cmd, "terminar %d", &pid) == 1)  det_terminar(pid, resp, sizeof resp);
        else snprintf(resp, sizeof resp, "Comando desconocido.\n");
        size_t l = strlen(resp);
        if (l && resp[l - 1] != '\n' && l + 1 < sizeof resp) { resp[l] = '\n'; resp[l + 1] = '\0'; }
    }
    if (write(cl, resp, strlen(resp)) < 0) { /* el cliente se fue */ }
    close(cl);
}

void ctl_cerrar(const config_t *c) { unlink(c->sock_file); }

int ctl_cliente(const config_t *c, const char *comando) {
    struct sockaddr_un a;
    if (ruta_sock(c, &a) != 0) return 1;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(stderr, "El guardián no está en ejecución (o falta sudo): %s\n", strerror(errno));
        return 1;
    }
    char m[160];
    int n = snprintf(m, sizeof m, "%s\n", comando);
    if (write(fd, m, (size_t)n) < 0) return 1;
    char buf[4096];
    ssize_t r;
    while ((r = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, (size_t)r, stdout);
    close(fd);
    return 0;
}
