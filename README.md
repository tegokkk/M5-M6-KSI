# RuangKampus — lab keamanan kampus

Portal full-stack JavaScript untuk latihan lokal. Frontend berada di `public/`; API dan SQLite berjalan dari `server.js`. Semua akun dan isi database bersifat sintetis. Server hanya listen pada `127.0.0.1`.

## Menjalankan

Persyaratan: Node.js 22.13 atau lebih baru dan npm.

```powershell
npm install
npm start
```

Buka `http://127.0.0.1:3000`. Hentikan server dengan `Ctrl+C`. Database dan berkas unggahan disimpan di `data/` dan dibuat saat server pertama kali berjalan. Untuk mengembalikan data awal, hentikan server lalu hapus folder `data/`.

## Akun demo

| Peran | Email | Kata sandi |
| --- | --- | --- |
| Mahasiswa | `tegosaputra@demo.test` | `mahasiswa123` |
| Mahasiswa | `raka@demo.test` | `raka12345` |
| Dosen | `rezaredo@demo.test` | `dosen123` |
| Admin | `admin@demo.test` | `admin123` |

## Fitur

- Mahasiswa melihat nilai, mengunggah PDF/TXT/DOCX, mengunduh tugas sendiri, dan berdiskusi.
- Dosen melihat kiriman tugas dan mengubah atau menambahkan nilai.
- Admin menambah, mengubah, dan menghapus akun sintetis.
- Login memakai sesi cookie; logout membatalkan sesi.
- Database SQLite lokal dengan kata sandi demo yang di-hash.

## Tiga kelemahan latihan yang disengaja

1. **SQL injection:** pencarian diskusi membangun query SQL dari parameter pencarian tanpa parameter binding. Contoh uji lokal di kotak cari: `' OR 1=1 -- `.
2. **IDOR:** endpoint nilai `GET /api/grades/:studentId` tidak memastikan bahwa mahasiswa hanya meminta ID miliknya sendiri. Di menu Nilai, ubah pratinjau ke mahasiswa lain.
3. **Tanpa pembatasan login:** endpoint `POST /api/login` tidak menerapkan rate limit atau lockout. Lima login gagal berurutan masih menerima respons gagal biasa.

Folder `nuclei/` berisi tiga template yang memeriksa perilaku tersebut pada lab. Jalankan server lokal, lalu dari jendela PowerShell lain:

```powershell
nuclei -u http://127.0.0.1:3000 -t .\nuclei\ruangkampus-sqli.yaml
nuclei -u http://127.0.0.1:3000 -t .\nuclei\ruangkampus-idor.yaml
nuclei -u http://127.0.0.1:3000 -t .\nuclei\ruangkampus-no-login-limit.yaml
```

Temuan SQLi dan IDOR mengonfirmasi respons data demo; template login mengirim lima kredensial gagal sintetis. Jalankan template hanya terhadap server latihan milik sendiri. **Jangan bind ke alamat publik atau meneruskan port server ke jaringan.** Kerentanan ini sengaja ada dan bukan untuk produksi.
