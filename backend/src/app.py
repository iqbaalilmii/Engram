import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os

# Membuat instance FastAPI
app = FastAPI()

# Menambahkan middleware untuk CORS (Cross-Origin Resource Sharing)
# Ini memungkinkan frontend (yang berjalan di domain berbeda jika dibuka sebagai file)
# untuk berkomunikasi dengan backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Mengizinkan semua origin
    allow_credentials=True,
    allow_methods=["*"],  # Mengizinkan Pisemua metode (GET, POST, dll.)
    allow_headers=["*"],  # Mengizinkan semua header
)

# Mendapatkan path absolut ke direktori frontend
# Ini penting agar path file benar di sistem operasi manapun.
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
index_html_path = os.path.join(frontend_dir, "index.html")

@app.get("/inprint")
async def read_index():
    """
    Endpoint ini akan menyajikan file index.html dari folder frontend.
    """
    return FileResponse(index_html_path)

@app.get("/api/data")
async def get_data():
    """
    Endpoint API sederhana yang mengembalikan data JSON.
    """
    return {"message": "Halo dari Backend FastAPI!", "project": "Proyek Keren"}

if __name__ == "__main__":
    # Menjalankan server menggunakan uvicorn di localhost pada port 3000
    uvicorn.run(app, host="0.0.0.0", port=3000)
