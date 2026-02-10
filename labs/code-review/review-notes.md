# Secure Code Review - <Nama Peserta>
Project: vulnerable.js
Tanggal: YYYY-MM-DD

## Summary (1–2 kalimat)
Ringkasan temuan dan prioritas (mis. "Ditemukan 5 issue, 2 high, 2 medium, 1 low").

## Findings (minimum 5)
1. **Issue:** SQL Injection  
   **Location:** /search handler (baris XX)  
   **Risk:** High — attacker bisa manipulasi query dan mengeksekusi query arbitrary.  
   **Recommendation:** Gunakan parameterized query / prepared statements. Contoh: `db.get("SELECT ... WHERE name LIKE ?", ['%'+q+'%'])`.

2. **Issue:** Stored XSS  
   **Location:** /comments render (baris XX)  
   **Risk:** High — payload tersimpan dan dieksekusi pada pengunjung.  
   **Recommendation:** Encode on output atau gunakan sanitizer (DOMPurify) sebelum render.

3. **Issue:** IDOR / Broken Access Control  
   **Location:** /product/:id (baris XX)  
   **Risk:** High — resource diakses tanpa authorization check.  
   **Recommendation:** Periksa ownership/permissions sebelum return resource.

4. **Issue:** Reflected XSS  
   **Location:** /reflect (baris XX)  
   **Risk:** Medium — input langsung direfleksikan ke page.  
   **Recommendation:** Escape output dan validasi input.

5. **Issue:** DOM-based XSS (client)  
   **Location:** /dom (script block)  
   **Risk:** Medium — penggunaan innerHTML dengan data dari location.hash.  
   **Recommendation:** Gunakan textContent / safe DOM APIs.

## Verification / How I tested
- Contoh request/URL yang saya pakai untuk reproduce (screen capture disertakan jika ada).

## Patch idea / Code snippet (singkat)
- Contoh prepared statement, contoh penggunaan `escapeHtml()` atau `textContent` replacement.

## Notes
- Prioritas: (High / Medium / Low)
- Keterangan tambahan / risiko bisnis
