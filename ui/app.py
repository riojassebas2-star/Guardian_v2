#!/usr/bin/env python3
"""Panel del Guardián Híbrido v2.

Toda la detección ocurre en el motor en C (guardian). Este panel solo:
  - lee el log JSONL que escribe el motor (de forma incremental),
  - inicia/detiene el motor (sudo, o systemctl si está instalado como servicio),
  - libera/termina procesos congelados y restaura archivos desde la bóveda,
  - edita la lista blanca.
"""
import csv
import json
import os
import shutil
import subprocess
import tempfile
import tkinter as tk
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    HAY_GRAFICO = True
except ImportError:          # el panel funciona igual sin gráfico
    HAY_GRAFICO = False

RAIZ = Path(__file__).resolve().parent.parent
if (RAIZ / "guardian").exists() or not Path("/etc/guardian/guardian.conf").exists():
    INSTALADO = False                       # modo desarrollo: todo dentro de la carpeta del proyecto
    GUARDIAN_BIN = RAIZ / "guardian"
    LOG_FILE = RAIZ / "logs" / "guardian_alertas.jsonl"
    PID_FILE = RAIZ / "logs" / "guardian.pid"
    WL_FILE = RAIZ / "config" / "whitelist.txt"
else:                                       # instalado como servicio
    INSTALADO = True
    GUARDIAN_BIN = Path(shutil.which("guardian") or "/usr/local/sbin/guardian")
    LOG_FILE = Path("/var/log/guardian/alertas.jsonl")
    PID_FILE = Path("/run/guardian.pid")
    WL_FILE = Path("/etc/guardian/whitelist.txt")

MAX_FILAS = 2000
NEUTRALIZA = ("CONGELADO", "TERMINADO", "BLOQUEADO")      # "RE-CONGELADO" también contiene CONGELADO
INTERPRETES = {"bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "node"}
COLORES = {"rojo": "#ffd6d6", "amarillo": "#fff3c4", "verde": "#d8f5d8"}


def nivel(r):
    accion = r.get("action", "")
    if "VERDE" in accion:
        return "verde"
    if any(k in accion for k in NEUTRALIZA) or "ROJO" in accion or r.get("score", 0) >= 90:
        return "rojo"
    return "amarillo"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Guardián Híbrido - Panel de control")
        self.geometry("1180x700")
        self.offset = 0
        self.por_dia = Counter()
        self.neutralizadas = Counter()
        self.filas = {}
        self._crear_widgets()
        self._refrescar()

    # ---------------- interfaz ----------------
    def _crear_widgets(self):
        sup = ttk.Frame(self, padding=8)
        sup.pack(fill="x")
        self.lbl_estado = ttk.Label(sup, text="", font=("TkDefaultFont", 11, "bold"))
        self.lbl_estado.pack(side="left")
        self.lbl_stats = ttk.Label(sup, text="")
        self.lbl_stats.pack(side="right")

        barra = ttk.Frame(self, padding=(8, 0))
        barra.pack(fill="x")
        self.btn_iniciar = ttk.Button(barra, text="▶ Iniciar", command=self.iniciar)
        self.btn_detener = ttk.Button(barra, text="■ Detener", command=self.detener)
        for b in (self.btn_iniciar, self.btn_detener):
            b.pack(side="left", padx=2)
        ttk.Separator(barra, orient="vertical").pack(side="left", fill="y", padx=6)
        for texto, cmd in (("Reanudar proceso", self.reanudar), ("Terminar proceso", self.terminar),
                           ("Restaurar archivos", self.restaurar), ("Estado del motor", self.estado),
                           ("Lista blanca", self.lista_blanca), ("Exportar CSV", self.exportar),
                           ("Purgar historial", self.purgar)):
            ttk.Button(barra, text=texto, command=cmd).pack(side="left", padx=2)

        cols = ("hora", "pid", "programa", "eventos", "puntaje", "accion")
        marco = ttk.Frame(self, padding=8)
        marco.pack(fill="both", expand=True)
        self.tabla = ttk.Treeview(marco, columns=cols, show="headings", height=14)
        for c, t, w in (("hora", "Hora", 140), ("pid", "PID", 70), ("programa", "Programa", 330),
                        ("eventos", "Eventos", 70), ("puntaje", "Puntaje", 70), ("accion", "Acción y señales", 440)):
            self.tabla.heading(c, text=t)
            self.tabla.column(c, width=w, anchor="w")
        for n, col in COLORES.items():
            self.tabla.tag_configure(n, background=col)
        sb = ttk.Scrollbar(marco, orient="vertical", command=self.tabla.yview)
        self.tabla.configure(yscrollcommand=sb.set)
        self.tabla.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tabla.bind("<Double-1>", self.detalle)

        if HAY_GRAFICO:
            self.fig = Figure(figsize=(6, 1.8), dpi=90)
            self.ax = self.fig.add_subplot(111)
            self.canvas = FigureCanvasTkAgg(self.fig, master=self)
            self.canvas.get_tk_widget().pack(fill="x", padx=8, pady=(0, 8))

    # ---------------- motor y privilegios ----------------
    def pid_guardian(self):
        try:
            pid = int(PID_FILE.read_text().strip())
            if Path(f"/proc/{pid}/comm").read_text().strip() == "guardian":
                return pid
        except (OSError, ValueError):
            pass
        return None

    def asegurar_sudo(self):
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            return True
        clave = simpledialog.askstring("Autenticación", "Contraseña de administrador (sudo):",
                                       show="*", parent=self)
        if not clave:
            return False
        r = subprocess.run(["sudo", "-S", "-v"], input=clave + "\n", text=True, capture_output=True)
        if r.returncode != 0:
            messagebox.showerror("Error", "Contraseña incorrecta.")
        return r.returncode == 0

    def sudo(self, *cmd, entrada=None):
        if not self.asegurar_sudo():
            return None
        return subprocess.run(["sudo", "-n", *cmd], input=entrada, text=True, capture_output=True)

    def guardian(self, *args):
        """Ejecuta un subcomando del motor (--liberar, --restaurar...) como root."""
        return self.sudo(str(GUARDIAN_BIN), *args)

    def iniciar(self):
        if self.pid_guardian():
            return
        if INSTALADO:
            self.sudo("systemctl", "start", "guardian")
            return
        if not GUARDIAN_BIN.exists():
            messagebox.showerror("Falta compilar", "No existe ./guardian. Ejecuta 'make' en la carpeta del proyecto.")
            return
        if not self.asegurar_sudo():
            return
        # Sin start_new_session: así sudo reutiliza la contraseña ya verificada (va ligada a la
        # terminal). setpgrp evita que Ctrl+C en la terminal mate al guardián. El error se
        # captura y se muestra, en vez de perderse.
        err = tempfile.TemporaryFile()
        proc = subprocess.Popen(["sudo", "-n", str(GUARDIAN_BIN)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=err, preexec_fn=os.setpgrp)
        self.after(2000, lambda: self._verificar_inicio(proc, err, 0))

    def _verificar_inicio(self, proc, err, intento):
        if self.pid_guardian():
            return
        if proc.poll() is not None:                      # terminó sin quedar activo: hubo un error
            err.seek(0)
            msg = err.read().decode("utf-8", "replace").strip() or f"El proceso salió con código {proc.returncode}."
            messagebox.showerror("No se pudo iniciar el guardián", msg[-900:])
        elif intento < 3:                                # sigue arrancando: se vuelve a comprobar
            self.after(2000, lambda: self._verificar_inicio(proc, err, intento + 1))

    def detener(self):
        pid = self.pid_guardian()
        if not pid:
            return
        if INSTALADO:
            self.sudo("systemctl", "stop", "guardian")
        else:
            self.sudo("kill", "-TERM", str(pid))

    def _pid_seleccionado(self):
        sel = self.tabla.selection()
        if not sel:
            messagebox.showinfo("Selecciona una fila", "Elige primero un proceso en la tabla.")
            return None
        pid = self.filas.get(sel[0], {}).get("pid")
        if not isinstance(pid, int) or pid <= 1:
            messagebox.showinfo("Sin proceso", "Esa fila no corresponde a un proceso concreto.")
            return None
        return pid

    def _mostrar(self, titulo, texto):
        win = tk.Toplevel(self)
        win.title(titulo)
        caja = scrolledtext.ScrolledText(win, width=100, height=24)
        caja.pack(padx=8, pady=8)
        caja.insert("end", texto)
        caja.configure(state="disabled")

    def reanudar(self):
        pid = self._pid_seleccionado()
        if pid:
            r = self.guardian("--liberar", str(pid))
            if r is not None:
                messagebox.showinfo("Reanudar", (r.stdout or r.stderr).strip() or "Listo.")

    def terminar(self):
        pid = self._pid_seleccionado()
        if pid and messagebox.askyesno("Confirmar", f"¿Terminar definitivamente el proceso {pid} y sus hijos?"):
            r = self.guardian("--terminar", str(pid))
            if r is not None:
                messagebox.showinfo("Terminar", (r.stdout or r.stderr).strip() or "Listo.")

    def restaurar(self):
        pid = self._pid_seleccionado()
        if not pid:
            return
        sim = self.guardian("--restaurar", "--pid", str(pid), "--simular")
        if sim is None:
            return
        salida = (sim.stdout or "") + (sim.stderr or "")
        self._mostrar("Simulación de restauración", salida or "Sin resultados.")
        if "por restaurar" in salida and "0 archivo(s)" not in salida.splitlines()[-1] and \
                messagebox.askyesno("Restaurar", "¿Restaurar estos archivos desde la bóveda?"):
            real = self.guardian("--restaurar", "--pid", str(pid))
            if real is not None:
                self._mostrar("Resultado de la restauración", (real.stdout or "") + (real.stderr or ""))

    def estado(self):
        r = self.guardian("--estado")
        if r is not None:
            self._mostrar("Estado del motor", (r.stdout or "") + (r.stderr or ""))

    # ---------------- log (lectura incremental) ----------------
    def _refrescar(self):
        pid = self.pid_guardian()
        self.lbl_estado.config(text=f"● VIGILANCIA ACTIVA (pid {pid})" if pid else "○ Vigilancia detenida",
                               foreground="#1a7f1a" if pid else "#a00000")
        self.btn_iniciar.state(["disabled"] if pid else ["!disabled"])
        self.btn_detener.state(["!disabled"] if pid else ["disabled"])
        if self._leer_nuevas():
            self._actualizar_stats()
        self.after(1500, self._refrescar)

    def _leer_nuevas(self):
        try:
            size = LOG_FILE.stat().st_size
        except OSError:
            return False
        if size < self.offset:                       # rotado o purgado
            self.tabla.delete(*self.tabla.get_children())
            self.filas.clear(); self.por_dia.clear(); self.neutralizadas.clear()
            self.offset = 0
        if size == self.offset:
            return False
        with open(LOG_FILE, "rb") as f:
            f.seek(self.offset)
            datos = f.read()
        fin = datos.rfind(b"\n") + 1                 # solo líneas completas
        self.offset += fin
        for linea in datos[:fin].decode("utf-8", "replace").splitlines():
            try:
                self._agregar(json.loads(linea))
            except json.JSONDecodeError:
                continue
        while len(self.filas) > MAX_FILAS:
            ultimo = self.tabla.get_children()[-1]
            self.tabla.delete(ultimo)
            self.filas.pop(ultimo, None)
        return fin > 0

    def _agregar(self, r):
        n = nivel(r)
        dia = str(r.get("timestamp", ""))[:10]
        if n != "verde":
            self.por_dia[dia] += 1
        if any(k in r.get("action", "") for k in NEUTRALIZA):
            self.neutralizadas[dia] += 1
        iid = self.tabla.insert("", 0, tags=(n,), values=(
            str(r.get("timestamp", "")).replace("T", " "), r.get("pid", ""), r.get("program", ""),
            r.get("files_touched", ""), r.get("score", ""), r.get("action", "")))
        self.filas[iid] = r

    def _actualizar_stats(self):
        dias = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        self.lbl_stats.config(text=f"Alertas (7 días): {sum(self.por_dia[d] for d in dias)}   |   "
                                   f"Amenazas contenidas: {sum(self.neutralizadas[d] for d in dias)}")
        if HAY_GRAFICO:
            self.ax.clear()
            self.ax.bar([d[5:] for d in dias], [self.por_dia[d] for d in dias], color="#c0392b")
            self.ax.set_title("Alertas por día (excluye eventos verdes)", fontsize=9)
            self.fig.tight_layout()
            self.canvas.draw_idle()

    # ---------------- utilidades ----------------
    def detalle(self, _e):
        sel = self.tabla.selection()
        if sel:
            messagebox.showinfo("Detalle del incidente", json.dumps(self.filas[sel[0]], indent=2, ensure_ascii=False))

    def exportar(self):
        ruta = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not ruta:
            return
        with open(ruta, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "pid", "program", "files_touched", "score", "action"])
            for iid in reversed(self.tabla.get_children()):
                r = self.filas[iid]
                w.writerow([r.get(k, "") for k in ("timestamp", "pid", "program", "files_touched", "score", "action")])
        messagebox.showinfo("Exportado", f"Historial guardado en {ruta}")

    def purgar(self):
        if not messagebox.askyesno("Purgar historial", "Se borrará el historial de alertas. ¿Continuar?"):
            return
        try:
            open(LOG_FILE, "w").close()
        except OSError:
            self.sudo("truncate", "-s", "0", str(LOG_FILE))

    def lista_blanca(self):
        win = tk.Toplevel(self)
        win.title("Lista blanca")
        ttk.Label(win, wraplength=400, padding=8, text=(
            "Nombre simple (apt): vale solo si el ejecutable está en /usr, /bin, /sbin, /lib, /opt o /snap.\n"
            "Ruta absoluta: coincidencia exacta; puedes fijar el binario con un hash:  /ruta/prog sha256=<64 hex>\n"
            "No agregues intérpretes (bash, python3...).")).pack()
        lista = tk.Listbox(win, width=60, height=12)
        lista.pack(padx=8)
        try:
            lineas = WL_FILE.read_text().splitlines()
        except OSError:
            lineas = []
        comentarios = [l for l in lineas if l.strip().startswith("#")]
        for e in (l.strip() for l in lineas if l.strip() and not l.strip().startswith("#")):
            lista.insert("end", e)
        campo = ttk.Entry(win, width=50)
        campo.pack(pady=4)

        def guardar():
            texto = "\n".join(comentarios + list(lista.get(0, "end"))) + "\n"
            try:
                WL_FILE.write_text(texto)
            except OSError:
                self.sudo("tee", str(WL_FILE), entrada=texto)

        def agregar():
            v = campo.get().strip()
            if not v or "#" in v:
                return
            if v.split()[0] in INTERPRETES:
                messagebox.showwarning("No permitido", f"'{v.split()[0]}' es un intérprete: permitirlo dejaría pasar cualquier script.")
                return
            lista.insert("end", v)
            campo.delete(0, "end")
            guardar()

        def quitar():
            for i in reversed(lista.curselection()):
                lista.delete(i)
            guardar()

        fila = ttk.Frame(win)
        fila.pack(pady=6)
        ttk.Button(fila, text="Agregar", command=agregar).pack(side="left", padx=4)
        ttk.Button(fila, text="Quitar seleccionado", command=quitar).pack(side="left", padx=4)


if __name__ == "__main__":
    App().mainloop()
