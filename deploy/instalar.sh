#!/bin/bash
# Instala el Guardián como servicio. Uso:  sudo deploy/instalar.sh
# (DESTDIR=/ruta permite instalar en una carpeta de prueba sin tocar el sistema.)
set -eu
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
D="${DESTDIR:-}"
[ "$(id -u)" -eq 0 ] || [ -n "$D" ] || { echo "Ejecuta con sudo: sudo $0"; exit 1; }
[ -x "$RAIZ/guardian" ] || make -C "$RAIZ"
USUARIO="${SUDO_USER:-${USER:-root}}"

install -d -m 0755 "$D/etc/guardian" "$D/usr/local/sbin" "$D/var/log/guardian" "$D/etc/systemd/system"
install -d -m 0700 "$D/var/lib/guardian" "$D/var/lib/guardian/boveda"
install -m 0755 "$RAIZ/guardian" "$D/usr/local/sbin/guardian"
sed "s/__USUARIO__/$USUARIO/" "$RAIZ/deploy/guardian.conf" > "$D/etc/guardian/guardian.conf"
chmod 0644 "$D/etc/guardian/guardian.conf"
if [ ! -f "$D/etc/guardian/whitelist.txt" ]; then
  install -m 0644 "$RAIZ/config/whitelist.txt" "$D/etc/guardian/whitelist.txt"
fi
install -m 0644 "$RAIZ/deploy/guardian.service" "$D/etc/systemd/system/guardian.service"
if [ -z "$D" ]; then
  chown -R root:root /etc/guardian /var/lib/guardian
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now guardian
    echo "Servicio activo:  systemctl status guardian"
  else
    echo "Sin systemd: arráncalo a mano con  sudo /usr/local/sbin/guardian"
  fi
fi
echo "Instalado para el usuario '$USUARIO'. Configuración: /etc/guardian/guardian.conf (solo root)."
