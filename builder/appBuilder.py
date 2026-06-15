import os
import sys
import subprocess
import csv
from datetime import datetime

# Menentukan path dasar
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDER_DIR = os.path.join(BASE_DIR, 'builder')
CONFIG_FILE = os.path.join(BUILDER_DIR, 'config.ini')
CSV_FILE = os.path.join(BUILDER_DIR, 'buildDate.csv')
FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')
BACKEND_DIR = os.path.join(BASE_DIR, 'backend')
APP_PY = os.path.join(BACKEND_DIR, 'src', 'app.py')

def read_config():
    """Membaca file konfigurasi sederhana tanpa section."""
    config = {}
    if not os.path.exists(CONFIG_FILE):
        return config
    
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if '=' in line:
                key, val = line.split('=', 1)
                config[key.strip()] = val.strip()
    return config

def write_config(config):
    """Menyimpan kembali file konfigurasi."""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        for key, val in config.items():
            f.write(f"{key} = {val}\n")

def main():
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: File konfigurasi tidak ditemukan di {CONFIG_FILE}")
        sys.exit(1)

    config = read_config()
    
    # Membaca nilai dari konfigurasi
    file_name = config.get('fileName', 'app')
    try:
        build_number = int(config.get('buildNumber', '1'))
    except ValueError:
        build_number = 1
        
    build_backend = config.get('buildBackendOnly', 'false').lower() == 'true'
    build_frontend = config.get('buildFrontendOnly', 'false').lower() == 'true'

    exe_name = f"{file_name}-{build_number}.exe"
    
    print(f"==================================================")
    print(f" Memulai proses build untuk: {exe_name}")
    print(f"==================================================")

    # 1. Build Frontend
    if build_frontend:
        print("\n---> [1/2] Membangun Frontend (React/Vite)...")
        try:
            # Install dependencies
            print("Menjalankan 'npm install'...")
            subprocess.run(["npm", "install"], cwd=FRONTEND_DIR, shell=True, check=True)
            
            # Build React app
            print("Menjalankan 'npm run build'...")
            subprocess.run(["npm", "run", "build"], cwd=FRONTEND_DIR, shell=True, check=True)
            print("Frontend berhasil di-build.")
        except subprocess.CalledProcessError as e:
            print(f"Error saat build frontend: {e}")
            sys.exit(1)
    else:
        print("\n---> [1/2] Build Frontend dilewati (buildFrontendOnly = false).")

    # 2. Build Backend (dan gabungkan dengan Frontend ke dalam 1 EXE)
    if build_backend:
        print("\n---> [2/2] Membangun Backend (FastAPI) menjadi file EXE...")
        try:
            # Pyinstaller menggunakan pemisah data ';' di Windows dan ':' di Unix
            data_separator = ';' if os.name == 'nt' else ':'
            
            # Kita sertakan seluruh folder frontend agar bisa diakses FastAPI
            add_data_arg = f"{FRONTEND_DIR}{data_separator}frontend"
            
            pyinstaller_cmd = [
                sys.executable, "-m", "PyInstaller",
                "--name", f"{file_name}-{build_number}",
                "--onefile",
                "--add-data", add_data_arg,
                "--clean",
                APP_PY
            ]
            
            # Menjalankan PyInstaller dari root directory agar dist/ masuk ke root
            subprocess.run(pyinstaller_cmd, cwd=BASE_DIR, shell=True, check=True)
            print(f"Backend berhasil di-build menjadi {exe_name}.")
        except subprocess.CalledProcessError as e:
            print(f"Error saat build backend: {e}")
            sys.exit(1)
    else:
        print("\n---> [2/2] Build Backend dilewati (buildBackendOnly = false).")

    # 3. Update buildNumber
    print("\n---> Memperbarui config.ini...")
    new_build_number = build_number + 1
    config['buildNumber'] = str(new_build_number)
    write_config(config)

    # 4. Mencatat ke CSV
    print(f"---> Mencatat riwayat build ke {CSV_FILE}...")
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")

    file_exists = os.path.exists(CSV_FILE)
    try:
        with open(CSV_FILE, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            # Tulis header jika file baru dibuat
            if not file_exists:
                writer.writerow(['FileName', 'Date', 'Time'])
            
            # Format: inprint-1.exe, 2026-06-15, 15:30:00
            writer.writerow([exe_name, date_str, time_str])
    except Exception as e:
        print(f"Gagal menulis ke CSV: {e}")

    print("\n==================================================")
    print(f" BUILD SELESAI!")
    print(f" Executable: dist/{exe_name}")
    print(f" Next Build Number: {new_build_number}")
    print("==================================================")

if __name__ == "__main__":
    main()