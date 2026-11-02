#!/bin/bash
# Prueba de extremo a extremo del Guardián v2. Requiere root.
# Usa un HOME temporal: no toca tu configuración, tus logs ni tus carpetas reales.
set -u
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo: sudo $0"; exit 1; }
[ -x "$RAIZ/guardian" ] || { echo "Compila primero: make"; exit 1; }

TMP="$(mktemp -d)"; ZONA="$TMP/zona"; ZONA2="$TMP/zona2"; LOG="$TMP/logs/guardian_alertas.jsonl"
mkdir -p "$TMP/config" "$TMP/logs" "$ZONA" "$ZONA2" "$TMP/bin"
SIM="$RAIZ/tests/simulador_estres"
cp "$SIM" "$TMP/bin/legitimo"
HASH=$(sha256sum "$TMP/bin/legitimo" | cut -d' ' -f1)
cat > "$TMP/config/guardian.conf" <<CFG
watch_dir=$ZONA
watch_dir=$ZONA2
net_activo=0
audit_dpkg=0
notificar=0
CFG
printf 'systemd\n%s sha256=%s\n' "$TMP/bin/legitimo" "$HASH" > "$TMP/config/whitelist.txt"
FALLOS=0
ok()    { echo "  [OK]    $1"; }
fallo() { echo "  [FALLO] $1"; FALLOS=$((FALLOS+1)); }
estado(){ awk '{print $3}' "/proc/$1/stat" 2>/dev/null; }
enlog() { grep -q "$1" "$LOG"; }
export GUARDIAN_HOME="$TMP"

# archivos originales para la prueba de recuperación (antes de arrancar el guardián)
for i in $(seq 0 199); do
  f=$(printf "%s/doc_%04d.txt" "$ZONA2" "$i")
  { echo "documento original $i"; head -c 3000 /dev/zero | tr '\0' 'x'; } > "$f"
done
( cd "$ZONA2" && sha256sum doc_*.txt ) > "$TMP/antes.sha"

"$RAIZ/guardian" > "$TMP/salida.txt" 2>&1 &
GPID=$!
sleep 1.5

echo "1) Canarios creados en las carpetas protegidas"
[ "$(ls "$ZONA" | grep -c -E '^(0000|zzzz)_')" -eq 4 ] && ok "4 canarios en la zona" || fallo "faltan canarios"

echo "2) Uso normal: 5 archivos y extracción de 1500 archivos nuevos (tar) -> sin alertas"
for i in 1 2 3 4 5; do echo hola > "$ZONA/normal_$i.txt"; done
mkdir "$TMP/pack"; for i in $(seq 1 1500); do echo "dato $i" > "$TMP/pack/nuevo_$i.txt"; done
tar -cf "$TMP/pack.tar" -C "$TMP/pack" .
timeout 25 tar -xf "$TMP/pack.tar" -C "$ZONA" || echo "  (tar no terminó: ¿fue congelado?)"
sleep 2
if grep -q -E 'CONGELADO|SOSPECHOSA' "$LOG"; then fallo "falso positivo con tar/archivos nuevos"; grep -E 'CONGELADO|SOSPECHOSA' "$LOG" | cut -c1-220; else ok "sin falsos positivos"; fi

echo "3) Ataque por renombrado desde un binario en C"
"$SIM" "$ZONA" 1000 renombrar > "$TMP/s1.txt" 2>&1 & S1=$!
sleep 3
[ "$(estado $S1)" = "T" ] && ok "simulador C congelado" || fallo "simulador C NO congelado"
kill -9 $S1 2>/dev/null; wait $S1 2>/dev/null

echo "4) Ataque desde un intérprete en /usr/bin (python3)"
python3 "$RAIZ/tests/simulador_estres.py" "$ZONA" 1000 > "$TMP/s2.txt" 2>&1 & S2=$!
sleep 3
[ "$(estado $S2)" = "T" ] && ok "simulador Python congelado" || fallo "simulador Python NO congelado"
kill -9 $S2 2>/dev/null; wait $S2 2>/dev/null

echo "5) Canario: una sola escritura basta (el proceso sigue vivo)"
python3 -c "import time; open('$ZONA/0000_documento_respaldo.docx','a').write('x'); time.sleep(60)" >/dev/null 2>&1 & S3=$!
sleep 2
[ "$(estado $S3)" = "T" ] && enlog 'canario' && ok "congelado al tocar un canario" || fallo "canario no detectado"

echo "6) Si alguien lo reanuda, se vuelve a congelar; --liberar lo suelta"
kill -CONT $S3 2>/dev/null; sleep 2.5
[ "$(estado $S3)" = "T" ] && ok "re-congelado tras SIGCONT" || fallo "no se re-congeló"
"$RAIZ/guardian" --liberar $S3 > "$TMP/lib.txt" 2>&1; sleep 3
[ "$(estado $S3)" != "T" ] && ok "liberado y sin re-congelar" || fallo "--liberar no funcionó"
kill -9 $S3 2>/dev/null; wait $S3 2>/dev/null

echo "7) Un binario llamado 'systemd' fuera de /usr no se hace pasar por legítimo"
cp "$SIM" /tmp/systemd_falso; cp /tmp/systemd_falso "$TMP/systemd"
"$TMP/systemd" "$ZONA" 600 renombrar > /dev/null 2>&1 & S4=$!
sleep 3
[ "$(estado $S4)" = "T" ] && ok "falso 'systemd' congelado" || fallo "falso systemd NO congelado"
kill -9 $S4 2>/dev/null; wait $S4 2>/dev/null; rm -f /tmp/systemd_falso

echo "8) Lista blanca con hash: binario íntegro pasa; el alterado no"
"$TMP/bin/legitimo" "$ZONA" 300 renombrar > "$TMP/l1.txt" 2>&1 & S5=$!
wait $S5 2>/dev/null
grep -q 'terminó' "$TMP/l1.txt" && ok "binario con hash correcto no fue tocado" || fallo "binario legítimo fue detenido"
echo "x" >> "$TMP/bin/legitimo"
"$TMP/bin/legitimo" "$ZONA" 600 renombrar > /dev/null 2>&1 & S6=$!
sleep 3
[ "$(estado $S6)" = "T" ] && ok "binario alterado (hash distinto) congelado" || fallo "binario alterado NO congelado"
kill -9 $S6 2>/dev/null; wait $S6 2>/dev/null

echo "9) Cifrado en sitio + restauración desde la bóveda"
"$SIM" "$ZONA2" 200 sobrescribir > "$TMP/s7.txt" 2>&1 & S7=$!
sleep 3
[ "$(estado $S7)" = "T" ] && ok "cifrador en sitio congelado (entropía)" || fallo "cifrador en sitio NO congelado"
enlog 'cifrado' && ok "motivo registrado: cifrado" || fallo "no se registró la señal de cifrado"
MAL=$( cd "$ZONA2" && sha256sum -c "$TMP/antes.sha" 2>/dev/null | grep -c FAILED )
[ "$MAL" -gt 0 ] && ok "hubo $MAL archivos dañados antes de frenarlo" || fallo "no se dañó ninguno (prueba inválida)"
"$RAIZ/guardian" --restaurar --pid $S7 > "$TMP/rest.txt" 2>&1
tail -1 "$TMP/rest.txt"
MAL2=$( cd "$ZONA2" && sha256sum -c "$TMP/antes.sha" 2>/dev/null | grep -c FAILED )
[ "$MAL2" -eq 0 ] && ok "todos los archivos restaurados idénticos al original" || fallo "quedaron $MAL2 archivos sin restaurar"
kill -9 $S7 2>/dev/null; wait $S7 2>/dev/null

echo "10) Cifra en otro archivo y BORRA el original -> detectado y restaurado"
"$SIM" "$ZONA2" 200 borrar > "$TMP/s8.txt" 2>&1 & S8=$!
sleep 3
[ "$(estado $S8)" = "T" ] && ok "cifrador-borrador congelado" || fallo "cifrador-borrador NO congelado"
FALTAN=$( cd "$ZONA2" && sha256sum -c "$TMP/antes.sha" 2>&1 | grep -c -E 'FAILED|No such' )
[ "$FALTAN" -gt 0 ] && ok "$FALTAN originales borrados antes de frenarlo" || fallo "no se borró ninguno (prueba inválida)"
"$RAIZ/guardian" --restaurar --pid $S8 > "$TMP/rest2.txt" 2>&1; tail -1 "$TMP/rest2.txt"
FALTAN2=$( cd "$ZONA2" && sha256sum -c "$TMP/antes.sha" 2>&1 | grep -c -E 'FAILED|No such' )
[ "$FALTAN2" -eq 0 ] && ok "originales borrados recreados idénticos" || fallo "faltan $FALTAN2 originales"
kill -9 $S8 2>/dev/null; wait $S8 2>/dev/null

echo "11) Nota de rescate"
python3 -c "
import time
for n in ('LEEME_DECRYPT_FILES.txt','HOW_TO_RECOVER_YOUR_FILES.txt'): open('$ZONA/'+n,'w').write('pague')
time.sleep(60)" >/dev/null 2>&1 & S9=$!
sleep 2
[ "$(estado $S9)" = "T" ] && enlog 'nota' && ok "congelado por notas de rescate" || fallo "notas de rescate no detectadas"
kill -9 $S9 2>/dev/null; wait $S9 2>/dev/null

echo "12) Ataque repartido entre procesos hijos: se detecta en el padre"
cat > "$TMP/padre.py" <<PYEOF
import subprocess, time
w = "import os,sys\nk=int(sys.argv[1])\nfor i in range(k*10,k*10+10):\n    open('$ZONA2/doc_%04d.txt'%i,'wb').write(os.urandom(4096))"
ps = [subprocess.Popen(["python3","-c",w,str(k)]) for k in range(8)]
time.sleep(60)
PYEOF
python3 "$TMP/padre.py" >/dev/null 2>&1 & S10=$!
sleep 4
[ "$(estado $S10)" = "T" ] && enlog 'árbol' && ok "padre congelado (ataque repartido en 8 procesos)" || fallo "ataque repartido no detectado"
pkill -9 -P $S10 2>/dev/null; kill -9 $S10 2>/dev/null; wait $S10 2>/dev/null

echo "13) Estado y log"

"$RAIZ/guardian" --estado > "$TMP/estado.txt" 2>&1
grep -q 'Bóveda' "$TMP/estado.txt" && grep -q 'congelados' "$TMP/estado.txt" && ok "--estado responde" || fallo "--estado falló"
python3 - "$LOG" <<'PY' && ok "todas las líneas del log son JSON válido" || fallo "JSON inválido en el log"
import json, sys
n = 0
for l in open(sys.argv[1]):
    json.loads(l); n += 1
sys.exit(0 if n else 1)
PY

kill -TERM $GPID; wait $GPID 2>/dev/null
echo "14) La salida del guardián no contiene errores de memoria"
if grep -q -E 'Sanitizer|runtime error' "$TMP/salida.txt"; then fallo "errores en la salida del guardián"; head -30 "$TMP/salida.txt"; else ok "salida limpia"; fi
echo; echo "--- Resumen del log ---"; cut -c1-230 "$LOG" | grep -v 'INICIADO\|DETENIDO' | tail -25
pkill -9 -f "$TMP" 2>/dev/null
rm -rf "$TMP"
[ $FALLOS -eq 0 ] && echo "TODAS LAS PRUEBAS PASARON" || echo "$FALLOS PRUEBA(S) FALLARON"
exit $FALLOS
