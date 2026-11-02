/* Guardián Híbrido v2 - cabecera común. Todo el núcleo está escrito en C. */
#ifndef GUARDIAN_H
#define GUARDIAN_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define GUARDIAN_VERSION "2.0"
#define PATH_LEN     512
#define MAX_DIRS     32
#define MAX_WL       128
#define NOMBRE_WL    128
#define NOMBRE_MAX   128
#define MAX_INODOS   128   /* archivos distintos que se recuerdan por ventana   */
#define CREADOS_N    256   /* nombres creados por un PID que se recuerdan       */

typedef enum { ACC_CONGELAR, ACC_TERMINAR, ACC_ALERTA } accion_t;

typedef struct { char nombre[NOMBRE_WL]; char sha[65]; } wl_t;

typedef struct {
    char   home[PATH_LEN], conf_dir[PATH_LEN];
    char   log_file[PATH_LEN], pid_file[PATH_LEN], sock_file[PATH_LEN];
    char   whitelist_file[PATH_LEN], vault_dir[PATH_LEN];
    int    sistema;               /* 1 = instalado (/etc/guardian): exige root:root */
    uid_t  owner_uid;  gid_t owner_gid;      /* usuario protegido (recibe canarios, avisos) */
    char   watch_dirs[MAX_DIRS][PATH_LEN];
    int    n_dirs;
    /* detección por comportamiento */
    int    umbral_eventos, umbral_archivos, ventana_seg, umbral_critico;
    int    entropia_x100;         /* 720 = 7.20 bits/byte */
    accion_t accion;
    /* canarios */
    int    canarios, canarios_prof;
    /* bóveda de recuperación */
    int    boveda;
    long   boveda_max_archivo, boveda_max_total;
    int    boveda_ttl_min;
    int    notificar;
    /* red */
    int    net_activo, net_bloquear;
    long   net_umbral_bytes;
    int    net_ventana_seg;
    int    audit_dpkg;
    wl_t   whitelist[MAX_WL];
    int    n_wl;
    long   wl_mtime;
} config_t;

/* config.c */
void config_ubicar(char *home, size_t nh, char *conf_dir, size_t nc, int *sistema);
int  config_cargar(config_t *c, const char *home, const char *conf_dir, int sistema);
int  config_whitelist_refrescar(config_t *c);        /* 1 si se recargó */
int  config_permisos(const config_t *c);              /* nº de problemas hallados */
int  wl_confiable(const config_t *c, const char *exe);
int  ruta_bajo_dirs(const config_t *c, const char *ruta);

/* sha256.c */
int  sha256_archivo(const char *ruta, char hex[65]);

/* logjson.c */
int  log_abrir(const char *ruta, uid_t uid, gid_t gid);
void log_alerta(int pid, const char *etiqueta, const char *programa,
                long volumen, int puntaje, const char *accion);
void log_cerrar(void);

/* pidtable.c : tabla hash (sondeo lineal + lápidas + LRU) con estadísticas por PID */
typedef struct {
    int       usado;              /* 0 vacío, 1 ocupado, 2 lápida */
    int       pid;                /* >0 proceso; <0 agregado del padre (-ppid) */
    long long ini_ventana, ultima, perdon_hasta;
    int       total, escrituras, nuevos, borrados, renombres, cifrados, notas, canario;
    int       n_inodos;
    uint64_t  inodos[MAX_INODOS];
    int       n_creados, pos_creados;
    uint32_t  creados[CREADOS_N];
    char      ult_from[NOMBRE_MAX];
    int       avisado, actuado, vault_n;
    int       ppid, ppid_listo, agrega_padre;
} pidstat_t;

pidstat_t *pt_obtener(int pid, long long ahora);
void       pt_ventana(pidstat_t *p, long long ahora, int ventana);
void       pt_purgar(long long ahora, int ttl);
int        pt_inodo(pidstat_t *p, uint64_t clave);       /* 1 si es nuevo en la ventana */
int        pt_es_creado(const pidstat_t *p, uint32_t h);
void       pt_add_creado(pidstat_t *p, uint32_t h);
uint32_t   hash_nombre(const char *s);

/* procinfo.c */
long long mono_seg(void);
int  pi_exe(int pid, char *out, size_t n);
int  pi_stat(int pid, char *estado, int *ppid, unsigned long long *inicio);
int  pi_ppid(int pid);
int  pi_descendientes(int pid, int *out, int max);
int  pi_es_shell(const char *exe);
int  pi_origen_sospechoso(const char *exe);
int  pi_buscar_pid_ip(uint32_t ip_be);
void hijo_registrar(int pid);
int  hijo_es(int pid);
void hijos_cosechar(void);

/* detect.c : puntaje por comportamiento, respuesta y registro de congelados */
void det_iniciar(const config_t *c, const char *exe_propio);
int  det_pid_confiable(int pid);
void det_escritura(int pid, uint64_t clave, const char *nombre, int cifrado, int reciente);
void det_creacion(int pid, const char *nombre);
void det_borrado(int pid, const char *nombre);
void det_mov_desde(int pid, const char *nombre);
void det_mov_hacia(int pid, const char *nombre);
void det_canario(int pid, const char *nombre, int borrado);
int  det_actuar_pid(int pid, const char **texto);     /* congela/termina según config */
void det_notificar(const char *titulo, const char *cuerpo);
void det_tick(long long ahora);
int  det_liberar(int pid, char *msg, size_t n);
int  det_terminar(int pid, char *msg, size_t n);
void det_estado(char *out, size_t n);

/* monitor.c : dos grupos fanotify (A: contenido + permisos, B: nombres) */
int  mon_iniciar(const config_t *c);
int  mon_fd_a(void);
int  mon_fd_b(void);
void mon_leer_a(void);
void mon_leer_b(void);
void mon_vaciar_a(void);
void mon_marcar_todo(void);
int  mon_rescan_pendiente(void);
void mon_cerrar(void);

/* boveda.c : copias previas de archivos y restauración */
int  bov_iniciar(const config_t *c);
void bov_preimagen(int fd, const char *ruta, int pid);
void bov_tick(long long ahora);
void bov_texto(char *out, size_t n);
int  bov_restaurar_cli(const config_t *c, int pid, int minutos, int simular);
int  bov_estado_cli(const config_t *c);

/* canario.c : archivos señuelo */
int  canario_es(const char *nombre);
void canarios_asegurar(const config_t *c);
void canarios_asegurar_async(const config_t *c);

/* control.c : socket de control root-only y cliente de línea de comandos */
int  ctl_iniciar(const config_t *c);
void ctl_atender(int fd);
void ctl_cerrar(const config_t *c);
int  ctl_cliente(const config_t *c, const char *comando);

/* netmon.c : sensor de exfiltración (AF_PACKET) */
int  net_iniciar(void);
void net_procesar(int fd);
void net_tick(const config_t *c, long long ahora);
void net_limpiar(void);

/* auditor.c */
void audit_dpkg_tick(void);

#endif
