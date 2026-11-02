#include "guardian.h"
#include <string.h>

#define PT_TAM 512
static pidstat_t tab[PT_TAM];

static pidstat_t *nuevo(int idx, int pid, long long ahora) {
    memset(&tab[idx], 0, sizeof tab[idx]);
    tab[idx].usado = 1;
    tab[idx].pid = pid;
    tab[idx].ini_ventana = tab[idx].ultima = ahora;
    return &tab[idx];
}

/* Búsqueda/inserción con sondeo lineal y lápidas. Si la tabla se llena se
 * desaloja la entrada menos usada recientemente (LRU). */
pidstat_t *pt_obtener(int pid, long long ahora) {
    int base = (int)((unsigned)pid % PT_TAM), lapida = -1;
    for (int i = 0; i < PT_TAM; i++) {
        int j = (base + i) % PT_TAM;
        if (tab[j].usado == 1 && tab[j].pid == pid) { tab[j].ultima = ahora; return &tab[j]; }
        if (tab[j].usado == 2 && lapida < 0) lapida = j;
        if (tab[j].usado == 0) return nuevo(lapida >= 0 ? lapida : j, pid, ahora);
    }
    if (lapida >= 0) return nuevo(lapida, pid, ahora);
    int lru = 0;
    for (int j = 1; j < PT_TAM; j++) if (tab[j].ultima < tab[lru].ultima) lru = j;
    return nuevo(lru, pid, ahora);
}

/* Ventana nueva: se reinician los contadores (el perdón y el padre se conservan). */
void pt_ventana(pidstat_t *p, long long ahora, int ventana) {
    if (ahora - p->ini_ventana < ventana) return;
    p->ini_ventana = ahora;
    p->total = p->escrituras = p->nuevos = p->borrados = 0;
    p->renombres = p->cifrados = p->notas = p->canario = 0;
    p->n_inodos = p->n_creados = p->pos_creados = 0;
    p->ult_from[0] = '\0';
    p->avisado = p->actuado = p->vault_n = 0;
}

void pt_purgar(long long ahora, int ttl) {
    for (int j = 0; j < PT_TAM; j++)
        if (tab[j].usado == 1 && ahora - tab[j].ultima > ttl) tab[j].usado = 2;
}

int pt_inodo(pidstat_t *p, uint64_t clave) {
    for (int i = 0; i < p->n_inodos; i++) if (p->inodos[i] == clave) return 0;
    if (p->n_inodos < MAX_INODOS) p->inodos[p->n_inodos++] = clave;
    return 1;
}

int pt_es_creado(const pidstat_t *p, uint32_t h) {
    for (int i = 0; i < p->n_creados; i++) if (p->creados[i] == h) return 1;
    return 0;
}

/* Anillo: si se crean más de CREADOS_N nombres, los más viejos se sobrescriben. */
void pt_add_creado(pidstat_t *p, uint32_t h) {
    p->creados[p->pos_creados] = h;
    p->pos_creados = (p->pos_creados + 1) % CREADOS_N;
    if (p->n_creados < CREADOS_N) p->n_creados++;
}

uint32_t hash_nombre(const char *s) {            /* FNV-1a 32 bits */
    uint32_t h = 2166136261u;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}
