import sys, os
import tkinter as tk
from tkinter import filedialog, messagebox
import hmac
import hashlib
import secrets

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# ===============================
# Funciones de lógica
# ===============================
def generar_token(key: bytes, counter: int) -> str:
    msg = f"counter:{counter}".encode()
    hm = hmac.new(key, msg, hashlib.sha256).digest()
    return hm.hex()

# ===============================
# Funciones de interfaz
# ===============================
def cargar_clave():
    """Permite cargar una clave desde un archivo .txt"""
    archivo = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])
    if archivo:
        try:
            with open(archivo, "r") as f:
                clave = f.read().strip()
            entry_clave.delete(0, tk.END)
            entry_clave.insert(0, clave)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo leer el archivo:\n{e}")

def generar_clave():
    """Genera una clave hexadecimal segura (256 bits por defecto) y la inserta en el campo de clave.
    También intenta copiarla al portapapeles y muestra una notificación al usuario.
    """
    # Generar 32 bytes (256 bits) -> 64 caracteres hex
    clave_hex = secrets.token_hex(32)
    entry_clave.delete(0, tk.END)
    entry_clave.insert(0, clave_hex)
    try:
        ventana.clipboard_clear()
        ventana.clipboard_append(clave_hex)
        messagebox.showinfo("Clave generada", "Se generó una clave hexadecimal y se copió al portapapeles.")
    except Exception:
        messagebox.showinfo("Clave generada", "Se generó una clave hexadecimal.")

def generar():
    """Genera los tokens en función de la clave y número de pasos"""
    clave_hex = entry_clave.get().strip()
    pasos_texto = entry_pasos.get().strip()

    if not clave_hex:
        messagebox.showwarning("Advertencia", "Debes ingresar o cargar una clave.")
        return
    if not pasos_texto.isdigit():
        messagebox.showwarning("Advertencia", "El número de pasos debe ser un número entero.")
        return

    try:
        key = bytes.fromhex(clave_hex)
    except ValueError:
        messagebox.showerror("Error", "La clave debe estar en formato hexadecimal válido.")
        return

    pasos = int(pasos_texto)
    if pasos <= 0:
        messagebox.showwarning("Advertencia", "El número de pasos debe ser mayor que 0.")
        return

    # Generar tokens
    text_resultado.delete("1.0", tk.END)
    for i in range(1, pasos + 1):
        token = generar_token(key, i)
        text_resultado.insert(tk.END, f"T{i} = {token}\n")

def guardar():
    """Guarda los tokens en un archivo .txt"""
    contenido = text_resultado.get("1.0", tk.END).strip()
    if not contenido:
        messagebox.showwarning("Advertencia", "No hay tokens para guardar. Genera primero.")
        return

    archivo = filedialog.asksaveasfilename(defaultextension=".txt",
                                           filetypes=[("Archivos de texto", "*.txt")])
    if archivo:
        try:
            with open(archivo, "w") as f:
                f.write(contenido)
            messagebox.showinfo("Éxito", f"Tokens guardados en:\n{archivo}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{e}")

# Nueva función: verificar un hash dado con la clave semilla y paso
def verificar_hash():
    """Verifica si un hash (hex) corresponde al token generado con la clave y paso indicados."""
    clave_hex = entry_clave.get().strip()
    hash_prov = entry_hash_verificar.get().strip()
    paso_text = entry_paso_verificar.get().strip()

    if not clave_hex:
        messagebox.showwarning("Advertencia", "Debes ingresar o cargar una clave.")
        return
    if not hash_prov:
        messagebox.showwarning("Advertencia", "Ingresa el token (hash) a verificar.")
        return
    if not paso_text.isdigit():
        messagebox.showwarning("Advertencia", "El número de paso debe ser un número entero.")
        return

    try:
        key = bytes.fromhex(clave_hex)
    except ValueError:
        messagebox.showerror("Error", "La clave debe estar en formato hexadecimal válido.")
        return

    paso = int(paso_text)
    if paso <= 0:
        messagebox.showwarning("Advertencia", "El número de paso debe ser mayor que 0.")
        return

    # Generar token esperado y comparar de forma segura
    esperado = generar_token(key, paso)
    valido = hmac.compare_digest(esperado, hash_prov.lower())

    if valido:
        messagebox.showinfo("Resultado", f"Válido: El token coincide para el paso {paso}.")
    else:
        messagebox.showinfo("Resultado", f"No válido: token esperado para paso {paso}:\n{esperado}")

# ===============================
# Construcción de la interfaz
# ===============================
ventana = tk.Tk()
ventana.title("Generador de Tokens HMAC-SHA256")
ventana.iconbitmap(resource_path("logo31.ico"))
ventana.geometry("750x450")

# Marco superior para clave
frame_clave = tk.Frame(ventana)
frame_clave.pack(pady=10, fill="x", padx=10)

tk.Label(frame_clave, text="Clave semilla (hex):").pack(side="left")
entry_clave = tk.Entry(frame_clave, width=66)
entry_clave.pack(side="left", padx=5)
btn_generar_clave = tk.Button(frame_clave, text="Generar clave", command=generar_clave)
btn_generar_clave.pack(side="left")
btn_cargar = tk.Button(frame_clave, text="Cargar desde archivo", command=cargar_clave)
btn_cargar.pack(side="left", padx=5)


# Marco para pasos
frame_pasos = tk.Frame(ventana)
frame_pasos.pack(pady=10, fill="x", padx=10)

tk.Label(frame_pasos, text="Número de pasos:").pack(side="left")
entry_pasos = tk.Entry(frame_pasos, width=10)
entry_pasos.pack(side="left", padx=5)

btn_generar = tk.Button(frame_pasos, text="Generar", command=generar)
btn_generar.pack(side="left", padx=10)

btn_guardar = tk.Button(frame_pasos, text="Guardar en archivo", command=guardar)
btn_guardar.pack(side="left", padx=10)

# Nuevo apartado: verificar un hash dado y el número de paso
frame_verificar = tk.LabelFrame(ventana, text="Verificar token", padx=10, pady=5)
frame_verificar.pack(pady=5, fill="x", padx=10)

tk.Label(frame_verificar, text="Token a verificar (hex):").pack(side="left")
entry_hash_verificar = tk.Entry(frame_verificar, width=60)
entry_hash_verificar.pack(side="left", padx=5)

tk.Label(frame_verificar, text="Paso:").pack(side="left", padx=(10,0))
entry_paso_verificar = tk.Entry(frame_verificar, width=6)
entry_paso_verificar.pack(side="left", padx=5)

btn_verificar = tk.Button(frame_verificar, text="Verificar", command=verificar_hash)
btn_verificar.pack(side="left", padx=10)

# Cuadro de texto para resultados
text_resultado = tk.Text(ventana, wrap="none", height=15)
text_resultado.pack(fill="both", expand=True, padx=10, pady=10)

ventana.mainloop()