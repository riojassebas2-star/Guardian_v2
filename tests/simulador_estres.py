#!/usr/bin/env python3
"""Mismo ataque simulado, pero desde un intérprete (/usr/bin/python3).
Sirve para comprobar que el guardián ya NO deja pasar procesos solo por vivir en /usr/bin."""
import os, sys, time

carpeta = sys.argv[1] if len(sys.argv) > 1 else "/tmp/zona_cuarentena_test"
cantidad = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
os.makedirs(carpeta, exist_ok=True)
print(f"[Simulador Py] pid {os.getpid()}: atacando {carpeta} con {cantidad} archivos", flush=True)
for i in range(cantidad):
    ruta = os.path.join(carpeta, f"doc_{i:04d}.txt")
    with open(ruta, "wb") as f:
        f.write(bytes([65 + i % 26]) * 1024)
    os.rename(ruta, ruta + ".locked_test")
    time.sleep(0.002)
print("[Simulador Py] terminó sin ser detenido.")
