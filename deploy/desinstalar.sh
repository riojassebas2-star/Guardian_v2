#!/bin/bash
# Quita el servicio. Con --purgar también borra la bóveda y los registros.
set -u
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo: sudo $0"; exit 1; }
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now guardian 2>/dev/null
fi
rm -f /usr/local/sbin/guardian /etc/systemd/system/guardian.service
rm -rf /etc/guardian
[ "${1:-}" = "--purgar" ] && rm -rf /var/lib/guardian /var/log/guardian
echo "Guardián desinstalado."
