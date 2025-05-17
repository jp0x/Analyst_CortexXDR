import os
import json
import pandas as pd
from openai import OpenAI
from dotenv import load_dotenv
import tkinter as tk
from tkinter import filedialog

# Cargar API Key desde .env
load_dotenv()
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY")
)

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

def generar_analisis_profesional(alerta_texto):
    prompt = f"""
Actúa como un analista de ciberseguridad del equipo MDR.

Dado el contenido crudo de una alerta (en formato JSON o TSV exportado desde Cortex XDR), tu tarea es generar un informe técnico completo siguiendo el flujo de análisis definido por MDR:

=== SECCIONES OBLIGATORIAS ===

1. Nombre de la alerta
2. Significado técnico y posible contexto de la alerta
3. Módulo o motor de detección (Analytics, BIOC, Local Analysis, etc.)
4. Principales atributos:
   - Usuario
   - Host
   - IP local y remota (si existe)
   - País (si aparece)
   - Ruta del ejecutable
   - Proceso padre
   - Hash SHA256
   - Firma digital
5. Revisión de antecedentes si hay evidencia de repitencia o historial
6. Acción tomada por la plataforma (bloqueo, cuarentena, solo detección, etc.)
7. Táctica y técnica MITRE ATT&CK si están presentes
8. Recomendaciones formales de respuesta
9. Conclusión técnica:
   - ¿Qué tipo de amenaza podría ser?
   - ¿Quién podría estar detrás? (APT, script kiddie, malware común, etc.)
   - ¿Cuál es el nivel de severidad real considerando MITRE?

Después de ese análisis, redacta 3 comentarios breves en español para dejar en el incidente.

Formato profesional. No uses emojis. Solo español.

Contenido de la alerta:
{alerta_texto}
    """.strip()

    completion = client.chat.completions.create(
        model="meta-llama/llama-3.3-8b-instruct:free",
        messages=[
            {"role": "user", "content": prompt}
        ],
        extra_headers={
            "HTTP-Referer": "https://yourdomain.com",
            "X-Title": "Analyst_CortexXDR"
        }
    )
    return completion.choices[0].message.content.strip()

def ejecutar_analisis():
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
        analisis = generar_analisis_profesional(alerta)
        print("\n--- Informe de análisis generado ---\n")
        print(analisis)
        with open("informe_alerta_mdr.txt", "w", encoding="utf-8") as f:
            f.write(analisis)
        print("\nInforme guardado como informe_alerta_mdr.txt")
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    print("== Analyst_CortexXDR – Análisis MDR Avanzado ==")
    ejecutar_analisis()