# **Imprint**
Team Name: "Bastion Seize"

backend python - fastAPI

frontend: HTML, CSS, React



Imprint adalah platform forensik memori yang menganalisis RAM dump secara otomatis untuk keperluan Incident Investigation ketika terjadi serangan digital. Seluruh proses analisis, mulai dari ekstraksi proses, deteksi injeksi malware, pemindaian YARA, berjalan dalam satu pipeline otomatis yang dapat diakses melalui browser di localhost.

Terinspirasi dari workflow Autopsy Forensic Browser, Imprint menghadirkan pengalaman yang sama untuk domain memory forensics cukup jalankan satu perintah, buka browser, dan analisis dimulai.
menggunakan python sebagai backend dan html sebagai frontend nya

# Latar Belakang

Serangan siber modern — khususnya yang digunakan dalam operasi Cyber Warfare — semakin banyak menggunakan teknik fileless malware: malware yang hanya hidup di RAM dan tidak meninggalkan jejak di disk. Teknik seperti:

Process Injection — menyuntikkan kode jahat ke proses Windows yang sah

Process Hollowing — mengosongkan proses legitim dan mengisinya dengan payload

Reflective DLL Injection — load malware langsung ke memori tanpa menyentuh disk

Living-off-the-Land (LotL) — menyalahgunakan tools bawaan OS seperti PowerShell dan WMI 


...tidak terdeteksi oleh antivirus konvensional. Satu-satunya cara menemukan jejaknya adalah melalui analisis RAM.

Masalahnya: tools yang ada seperti Volatility 3 masih berbasis CLI dan membutuhkan keahlian tinggi. Proses analisis yang seharusnya bisa diselesaikan dalam menit, bisa memakan waktu berjam-jam secara manual.

Imprint hadir untuk mengotomasi seluruh pipeline ini, memangkas waktu analisis dari berjam-jam menjadi menit, sehingga tim respons insiden dapat bergerak lebih cepat dari ancaman.

aplikasi berjalan di localhost di browser 
