import os
import json
import pandas as pd
import openai
from dotenv import load_dotenv
import tkinter as tk
from tkinter import filedialog

# Cargar clave API desde .env
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

def cargar_alerta(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".json":
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return json.dumps(data, indent=2)
    elif ext == ".tsv":
        df = pd.read_csv(file_path, sep="\t")
        return df.to_csv(index=False)
    else:
        raise ValueError("Formato no soportado. Usa .json o .tsv")

def generar_resumen_con_gpt(alerta_texto):
    prompt = f"""
Eres un analista de ciberseguridad. Dado el siguiente contenido de alerta, genera un resumen profesional incluyendo:
1. Significado de la alerta.
2. Módulo que detectó la amenaza.
3. Principales atributos del incidente (usuario, host, archivo, hash, etc).
4. Acción tomada por la plataforma.
5. Recomendaciones claras.
Formato profesional, sin emojis, y en español.

Contenido de la alerta:
{alerta_texto}
    """.strip()

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=1000
    )
    return response.choices[0].message.content.strip()

def ejecutar_analisis_desde_explorador():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Selecciona una alerta JSON o TSV",
        filetypes=[("Archivos JSON y TSV", "*.json *.tsv")]
    )
    if not file_path:
        print("No se seleccionó archivo.")
        return
    print(f"\nArchivo seleccionado: {file_path}\n")
    try:
        alerta = cargar_alerta(file_path)
        resumen = generar_resumen_con_gpt(alerta)
        print("\n--- Resumen generado ---\n")
        print(resumen)
        with open("resumen_alerta.txt", "w", encoding="utf-8") as f:
            f.write(resumen)
        print("\nResumen guardado en resumen_alerta.txt")
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    print("== Analyst_CortexXDR ==")
    ejecutar_analisis_desde_explorador()