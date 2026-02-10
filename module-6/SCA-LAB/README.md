# Software Composition Analysis (SCA) Lab

## Tujuan Pembelajaran
Melatih peserta menemukan dan memperbaiki dependency rentan menggunakan tool SCA sesuai bahasa pemrograman masing-masing:
- Node / React / Express → `npm audit` atau `snyk`
- PHP → `composer audit`
- Go → `govulncheck`

Peserta akan melihat hasil **before / after fix** lalu membuat commit dengan perbaikan dependency.

---

## ⚙️ Persiapan Umum
1. Gunakan folder lab sesuai stack Anda (misalnya `sca-lab-node`, `sca-lab-php`, `sca-lab-go`).
2. Pastikan internet aktif untuk fetch vulnerability database.
3. Pastikan tool sesuai stack sudah terinstal:
   - Node: `npm` (v9+) atau `yarn`
   - PHP: `composer` (v2.4+)
   - Go: `go` (v1.20+)
   - React: gunakan Node/npm juga

---

## 🧰 A. Node / Express / React (npm audit)
# Langkah
  - Instal dependency
  - Jalankan audit
  - Catat hasil (before) → ss_sca_before_node.png
  - Perbaiki dependency rentan:
  - Jalankan audit ulang → pastikan “found 0 vulnerabilities”.
  - Catat hasil (after) → ss_sca_after_node.png

### 📦 Simulasi Package.json (dummy vuln)
Contoh `package.json` berisi versi lama:
```json
{
  "name": "sca-lab-node",
  "version": "1.0.0",
  "dependencies": {
    "axios": "0.19.0",
  }
}


---

