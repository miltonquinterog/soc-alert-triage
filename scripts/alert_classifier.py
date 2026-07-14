from pathlib import Path
import pandas as pd

# Clasificacion de eventos por severidad
severity = {
    4624: "Low",
    4625: "Medium",
    4672: "High",
    4688: "Medium",
    4720: "Critical",
    4728: "Critical",
}        

# Obtener la carpeta raíz del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent

# Ruta al archivo CSV
csv_file = BASE_DIR / "data"/ "windows_security.csv"


# Leer el archivo                                
print(BASE_DIR)
print(csv_file)
df = pd.read_csv(csv_file)

# Agregar la columna Severity
df["Severity"] = df["EventID"].map(severity)


print("=" * 50)
print("SOC ALERT TRIAGE")
print("=" * 50)

print(f"\nTotal de eventos: {len(df)}")

print("\nEventos encontrados:\n")

print(
    df[
        [
            "Timestamp",
            "EventID",
            "Severity",
            "Username",
            "SourceIP",
        ]    
    ]
)

# Guardar el resultado en un nuevo archivo CSV
output_file = BASE_DIR / "reports" / "classified_events.csv"


df.to_csv(output_file, index=False)


print("\nReporte generado correctamente:")
print(output_file)

