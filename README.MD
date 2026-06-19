# 🧠 Engram

> **Automated Volatile Memory Forensics Platform**
> Developed by Team: **"Bastion Seize"**

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![Tailwind](https://img.shields.io/badge/TailwindCSS-3.x-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)
![Volatility](https://img.shields.io/badge/Volatility-3-CC0000?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)

---

## 📌 Sekilas Tentang Engram

**Engram** adalah platform forensik memori (*volatile memory forensics*) modern yang mendeteksi, menganalisis, dan memvisualisasikan *RAM dump* secara otomatis untuk keperluan investigasi insiden (*Incident Response*).

Terinspirasi dari alur kerja *Autopsy Forensic Browser*, **Engram** membawa kekuatan analisis memori tingkat dalam ke dalam antarmuka web yang intuitif. Cukup unggah *memory dump* atau masukkan path direktori dump Anda, dan biarkan pipeline otomatis kami membedah memori di latar belakang — sementara Anda menganalisis hasilnya langsung dari browser di `localhost`.

---

## 🖥️ Demo

<p align="center">
  <img src="https://github.com/user-attachments/assets/7ed41447-3050-4952-a4ff-d65c3c25d25c" alt="Engram - Cases Dashboard" width="100%" />
  <br/><em>Cases Dashboard — manajemen sesi investigasi</em>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/72edfe1c-d57a-4970-9dcb-fca08b1d7ac9" alt="Engram - Analysis Panel" width="100%" />
  <br/><em>Analysis Panel — korelasi proses, jaringan, dan memori</em>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/3298c27e-cf99-4249-896d-a56e313ca021" alt="Engram - IOC & Threat Intel" width="100%" />
  <br/><em>IOC Automated List — ekstraksi indikator kompromi dengan skor VirusTotal</em>
</p>

---

## 💥 Latar Belakang & Masalah

Serangan siber modern — terutama dalam operasi *Cyber Warfare* tingkat tinggi — semakin bergantung pada teknik **Fileless Malware**. Ini adalah jenis malware yang hanya hidup di dalam RAM dan tidak meninggalkan jejak fisik di *harddisk*.

Beberapa teknik manipulasi memori evasif yang sering digunakan meliputi:

| Teknik | Deskripsi |
|--------|-----------|
| **Process Injection** | Menyuntikkan kode jahat ke dalam proses Windows yang sah (e.g., `rundll32.exe`) |
| **Process Hollowing** | Mengosongkan memori proses legitim dan menggantinya dengan payload berbahaya |
| **Reflective DLL Injection** | Memuat DLL malware langsung ke memori tanpa menyentuh *disk* |
| **Living-off-the-Land (LotL)** | Menyalahgunakan tools bawaan OS seperti PowerShell untuk mengeksekusi perintah jahat |

**Masalahnya:** Antivirus konvensional tidak mampu mendeteksi aktivitas ini karena hanya memindai *disk*. Alat standar industri seperti **Volatility 3** sangat kuat, tetapi murni berbasis CLI dan membutuhkan keahlian teknis tinggi. Proses korelasi data manual antara daftar proses, koneksi jaringan, dan injeksi memori bisa memakan waktu **berjam-jam**.

**Solusi Kami:** **Engram** mengotomatisasi seluruh pipeline forensik ini — memangkas waktu investigasi dari hitungan jam menjadi **menit**, dengan visualisasi korelasi data instan bagi tim analis SOC dan *Incident Responder*.

---

## 📋 Prerequisites

Pastikan sistem Anda telah memiliki:

- **Docker** & **Docker Compose** (direkomendasikan)
- **Python 3.11+** (jika menjalankan tanpa Docker)
- **Node.js 18+** (jika menjalankan tanpa Docker)
- File memory dump (format: `.raw`, `.mem`, `.vmem`, `.dmp`)
- **VirusTotal API Key** — [daftar gratis di sini](https://www.virustotal.com/gui/join-us)
- RAM minimal **8 GB** pada host (untuk analisis dump besar)

---

## ⚡ Quick Start

### Dengan Docker (Direkomendasikan)

```bash
# 1. Clone repositori
git clone https://github.com/bastion-seize/engram.git
cd engram

# 2. Salin file konfigurasi environment
cp .env.example .env
# Edit .env dan isi VIRUSTOTAL_API_KEY dengan API key Anda

# 3. Jalankan semua service
docker-compose up --build

# 4. Buka browser
# Frontend : http://localhost:3000
# API Docs : http://localhost:8000/docs
```

### Tanpa Docker (Manual)

```bash
# --- Backend ---
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# --- Frontend (terminal baru) ---
cd frontend
npm install
npm run dev
```

---

## 📖 Cara Penggunaan

1. **Buka** `http://localhost:3000` di browser
2. **Unggah** file memory dump **atau** masukkan path direktori tempat dump disimpan
3. **Analisis berjalan otomatis** — pipeline Volatility 3 akan langsung memproses dump di background
4. **Pantau** hasil investigasi secara real-time melalui 4 panel dashboard:
   - Identifikasi proses mencurigakan di **Process List Tracker**
   - Lacak koneksi C2 di **Network Connections Monitor**
   - Temukan injeksi memori di **Malfind Analyzer**
   - Review IOC dengan skor threat intel di **IOC Automated List**

---

## 🛠️ Arsitektur Teknologi

Engram dibangun dengan arsitektur client-server yang berjalan **sepenuhnya lokal** untuk memastikan keamanan dan privasi data sensitif.

```
┌─────────────────────────────────────────────┐
│                  Browser                    │
│           React.js + Tailwind CSS           │
│         (SOC-style Dashboard UI)            │
└────────────────────┬────────────────────────┘
                     │ HTTP / REST API
┌────────────────────▼────────────────────────┐
│            Backend (FastAPI)                │
│   • Upload Handler & Job Queue (Async)      │
│   • Volatility 3 Plugin Runner              │
│   • Output Parser (Text → JSON)             │
│   • VirusTotal OSINT Integration            │
└──────────┬──────────────────────┬───────────┘
           │                      │
┌──────────▼──────────┐  ┌───────▼──────────┐
│    Volatility 3     │  │   VirusTotal API  │
│  (Forensics Engine) │  │  (Threat Intel)   │
└─────────────────────┘  └──────────────────┘
```

| Layer | Teknologi | Peran |
|-------|-----------|-------|
| **Frontend** | React.js, Tailwind CSS | Dashboard SOC interaktif |
| **Backend** | Python, FastAPI | Orchestrator pipeline forensik |
| **Forensics Engine** | Volatility 3 | Ekstraksi & analisis artefak memori |
| **Threat Intel** | VirusTotal API | Scoring reputasi IP, Domain, Hash |

---

## 🚀 Fitur Utama (Core Panels)

### 1. 🔵 Process List Tracker
Menganalisis pohon proses (`pslist` / `pstree`), melacak Parent PID (PPID), dan otomatis **menandai merah** proses fileless yang tidak memiliki path file yang jelas di disk — indikator kuat adanya Process Injection atau Hollowing.

### 2. 🟡 Network Connections Monitor
Memetakan sisa-sisa struktur data jaringan (`netscan`) untuk mencocokkan PID lokal dengan IP/Domain asing — mendeteksi aktivitas **C2 Beaconing** secara otomatis.

### 3. 🔴 Malfind Analyzer
Menyisir memori VAD (*Virtual Address Descriptor*) untuk memburu proteksi memori mencurigakan seperti `PAGE_EXECUTE_READWRITE` (RWX) — signature klasik dari shellcode injection.

### 4. 🟢 IOC Automated List
Ekstraksi otomatis Indikator Kompromi (IP, Domain, dan Hash) dari seluruh hasil analisis, dilengkapi **skor reputasi intelijen ancaman** dari VirusTotal.

---

## 📊 Sample Output

Diuji menggunakan sample dump publik dari [MemLabs](https://github.com/stuxnet999/MemLabs):

```
File     : memdump.raw (4.2 GB)
OS Target: Windows 10 x64

✅ Analisis selesai dalam: ~4 menit 30 detik

📋 Ringkasan:
  • Proses mencurigakan ditemukan : 3
  • Koneksi jaringan aktif        : 12 (2 flagged)
  • Region memori RWX (Malfind)   : 7
  • IOC diekstrak                 : 5 IP, 2 Domain, 3 Hash
  • Threat Intel hits (VT)        : 2 IP dengan skor berbahaya (45/72, 38/72)
```

> ⚠️ *Hasil aktual bervariasi tergantung kondisi memory dump dan sistem target.*

---

## ⚠️ Limitations

Transparansi adalah bagian dari profesionalisme. Berikut batasan yang perlu diketahui:

- **Platform**: Saat ini hanya mendukung **Windows memory dump**. Dukungan Linux menyusul.
- **Malfind Noise**: Plugin Malfind secara inheren menghasilkan false positive. Review manual oleh analis tetap diperlukan.
- **Ukuran File**: Diuji hingga dump berukuran **~8 GB**. Dump lebih besar mungkin memerlukan resource tambahan.
- **Konektivitas**: Fitur IOC scoring memerlukan koneksi internet untuk mengakses VirusTotal API.
- **API Rate Limit**: VirusTotal tier gratis dibatasi 4 request/menit — analisis IOC besar akan berjalan lebih lambat.

---

## 👥 Tim Bastion Seize

| Nama | Role |
|------|------|
| **Ivan Aryasatya** | Backend Engineer |
| **Radisty Kirana Dhisa** | Frontend Engineer |
| **Iqbal Ilmi** | Forensics Analyst |

---

## 📄 Lisensi

Didistribusikan di bawah lisensi **MIT**. Lihat [`LICENSE`](LICENSE) untuk detail.

---

<div align="center">
  <sub>Built with ❤️ by Team Bastion Seize · Hackathon 2025</sub>
</div>
