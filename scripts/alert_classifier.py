from pathlib import Path
import pandas as pd

# Obtener la carpeta raíz del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent

# Ruta al archivo CSV
csv_file = BASE_DIR / "data"/ "windows_security.csv"

# Leer el archivo                                
print(BASE_DIR)
print(csv_file)
df = pd.read_csv(csv_file)

# Mostrar las primeras filas
print(df.head())
