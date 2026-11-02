# Guardián Híbrido v2

Sistema de **detección, contención y recuperación** ante ransomware y fuga de datos en Linux.
**El núcleo está escrito en C** (~2 500 líneas, sin dependencias externas). Python solo se usa
para el panel gráfico opcional.

## Qué hace

| Capa | Cómo |
|---|---|
| **Detección** | Dos grupos `fanotify` informan el PID real de cada escritura, creación, renombrado y borrado. Por proceso y ventana de tiempo se calcula un puntaje con varias señales (ver abajo). |
| **Señuelos** | Archivos *canario* en las carpetas protegidas (`0000_…`, `zzzz_…`). Escribir o renombrar uno = detección inmediata. |
| **Contención** | `SIGSTOP`/`SIGKILL` sobre el **árbol** de procesos. Si alguien reanuda un proceso congelado, se vuelve a congelar. Si el ataque se reparte entre hijos, se detecta en el padre. |
| **Recuperación** | Antes de que un proceso no confiable abra un archivo, se guarda una copia en una **bóveda de root**. `guardian --restaurar` devuelve los archivos tocados por el atacante. |
| **Red** | Sensor `AF_PACKET`: bytes salientes por IP pública; opcionalmente bloquea con `iptables`. |
| **Resiliencia** | Servicio systemd con watchdog, protección contra el OOM killer, memoria bloqueada, verificación de integridad del binario, configuración que debe ser `root:root`. |

### Señales del puntaje
- **ritmo**: reescritura de archivos *preexistentes* (crear archivos nuevos —`tar`, `git`, compilar— no cuenta).
- **cifrado**: escrituras con entropía > 7.2 bits/byte **y** sin cabecera de formato conocido (`.zip`, `.jpg`, `.pdf`, `.mp4`… legítimos sí la tienen).
- **renombres**: se agrega un sufijo (`doc.txt` → `doc.txt.xyz`) o se usa una extensión típica de ransomware.
- **nota**: creación de archivos con nombre de nota de rescate.
- **canario**: tocar un señuelo (100 puntos directos).
- Amplificadores: borrados masivos, varias señales a la vez, ejecutable lanzado desde `/tmp`, `/dev/shm` o `memfd`.

Desde `umbral_critico` (90) se actúa; entre 60 y 89 queda como alerta amarilla.

## Instalación y uso

```bash
sudo apt install build-essential python3-tk python3-matplotlib   # una vez
make                                  # compila ./guardian y el simulador
sudo ./guardian                       # modo desarrollo (config en ./config)
python3 ui/app.py                     # panel (opcional)

make install                          # como servicio: /usr/local/sbin, /etc/guardian, systemd
```

```text
sudo guardian --estado                        estado del motor en marcha
sudo guardian --liberar PID                   reanuda un proceso congelado
sudo guardian --terminar PID                  termina un proceso y sus hijos
sudo guardian --boveda                        resumen de la bóveda
sudo guardian --restaurar --pid N --simular   muestra qué se restauraría
sudo guardian --restaurar --pid N             restaura los archivos que tocó el proceso N
```

`--restaurar` sin `--pid` usa `--minutos M` y toma la copia más antigua de cada archivo en esa ventana;
**puede revertir ediciones legítimas** hechas dentro de ella, por eso se recomienda usar `--pid`.

## Configuración

`config/guardian.conf` (desarrollo) o `/etc/guardian/guardian.conf` (servicio, solo root). Claves principales:
`watch_dir` (repetible, admite `~`), `ventana_seg`, `umbral_eventos`, `umbral_critico`, `entropia`,
`accion` (`congelar`/`terminar`/`alerta`), `canarios`, `boveda`, `boveda_ttl_min`, `net_modo`.
`whitelist.txt` lista procesos legítimos; un nombre simple solo vale si el ejecutable está en un directorio
de sistema, y se puede fijar el binario con `/ruta/prog sha256=<hash>`. **No agregues intérpretes** (`bash`, `python3`).

## Pruebas

```bash
make test         # 14 comprobaciones de extremo a extremo (usa sudo y carpetas temporales)
make test-asan    # lo mismo con AddressSanitizer + UBSan
```
Cubren: canarios, uso normal sin falsos positivos (extracción de 1 500 archivos con `tar`), ataque por
renombrado desde C y desde `python3`, cifrado en sitio y borrado de originales **con restauración idéntica**,
notas de rescate, ataque repartido entre procesos, suplantación de nombre (`systemd` falso), lista blanca con
hash, re-congelado y `--liberar`, y log JSON válido.

## Limitaciones conocidas
- Detecta y contiene **después** de que el ataque empieza: se pierden los primeros archivos si no estaban en la
  bóveda (solo se copian los que un proceso no confiable llega a abrir, hasta 16 MB cada uno).
- Un atacante con **root** puede matar o detener al guardián; systemd lo reinicia, pero no es una barrera absoluta.
- La bóveda no reemplaza a un respaldo **externo y desconectado**.
- No ve ataques por red (SMB/NFS), solo sistemas de archivos locales; el sensor de red cubre solo IPv4.
- Las aperturas de archivos en carpetas protegidas esperan un instante a que el guardián copie el original;
  si el guardián se detuviera, el núcleo libera esas aperturas al cerrarse su descriptor.
- Probado en Ubuntu 24.04 (kernel ≥ 5.9 requerido). **No probados en este entorno:** el servicio systemd real,
  las notificaciones de escritorio y el bloqueo con `iptables`.
