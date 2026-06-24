# Penjelasan Paper SeqSQLi — Bahasa Indonesia Sederhana

> Versi mudah dipahami dari paper:
> "SeqSQLi: Sequential SQL Injection WAF Bypass via Deep Reinforcement Learning"

---

## Apa inti masalahnya?

Website menggunakan **Web Application Firewall (WAF)** untuk melindungi diri dari serangan SQL Injection.
WAF bekerja seperti satpam: ia membaca setiap permintaan yang masuk dan memblokir yang terlihat berbahaya.

Masalahnya: satpam ini mengenali bahaya hanya dari **penampilannya**, bukan dari **maknanya**.

Contoh sederhana:
- `SELECT * FROM users` → diblokir WAF ✗
- `SeLeCt  *  fRoM  uSeRs` → mungkin lolos ✓ (makna SQL sama persis)

Ini disebut **bypass WAF** — mengubah tampilan perintah SQL tanpa mengubah apa yang dilakukannya.

**Masalah yang belum terjawab sebelumnya:** bagaimana menemukan urutan perubahan yang tepat secara otomatis, tanpa trial-and-error manual?

---

## Solusi yang diusulkan: SeqSQLi

SeqSQLi mengajarkan sebuah **agen kecerdasan buatan** untuk belajar sendiri cara melewati WAF.

Bayangkan seperti seseorang yang bermain game:
- Setiap "giliran", agen memilih satu jenis modifikasi (misalnya: ubah huruf kecil-besar)
- WAF merespons: blokir atau lolos
- Agen mendapat nilai sesuai hasilnya
- Lama-lama, agen belajar kombinasi dan urutan modifikasi yang paling efektif

Ini adalah **Reinforcement Learning (RL)** — belajar dari coba-coba dengan umpan balik.

---

## Bagaimana agen "melihat" situasinya? (State / Pengamatan)

Agen melihat kondisi saat ini lewat **67 angka** (disebut vektor observasi):

| Bagian | Jumlah angka | Apa artinya? |
|--------|-------------|--------------|
| Fitur payload | 14 | Modifikasi apa yang sudah diterapkan? Ada encoding hex? Ada komentar? |
| Tipe injeksi | 1 | Ini serangan union atau error? |
| Aksi terakhir | 51 | Modifikasi terakhir apa yang dipilih? |
| Posisi langkah | 1 | Ini langkah ke berapa dari maksimal 15? |
| **Total** | **67** | |

Angka-angka ini memungkinkan agen tahu "posisinya" saat ini dan memilih langkah berikutnya.

---

## Apa yang bisa dilakukan agen? (Action Space / Pilihan Aksi)

Agen punya **51 operator modifikasi** yang bisa dipilih, dikelompokkan dalam 9 kategori:

| Kategori | Contoh | Efeknya |
|----------|--------|---------|
| Ganti huruf besar-kecil | `SeLeCt` | WAF tidak mengenali pola `select` |
| Ganti spasi | Tab, newline, `%0a` | Melewati aturan spasi |
| Sisipkan komentar | `SEL/**/ECT` | Memecah kata kunci |
| Encode hex | `0x3a` | Menyamarkan karakter |
| Trik identifier | `` `users` `` | Membungkus nama tabel |
| Ganti fungsi agregat | `JSON_ARRAYAGG(CONCAT())` | Mengganti `GROUP_CONCAT` |
| Null byte | `%00` | Memotong pengecekan |
| Trik tanda kurung | `func( )` | Menambah spasi dalam fungsi |
| Substitusi semantik | `AND → &&` | Ekuivalen secara SQL |

Semua operator ini **tidak mengubah makna SQL** — hanya tampilannya.

---

## Bagaimana agen mendapat nilai? (Reward Function)

Setiap langkah, agen mendapat nilai berdasarkan respons WAF:

| Hasil | Nilai | Artinya |
|-------|-------|---------|
| SUCCESS | +10 | WAF terlewati, data berhasil diambil 🎉 |
| SQL_ERROR | +0.5 | Payload masuk tapi ada error SQL |
| FILTERED | −1 | WAF memblokir |
| UNKNOWN | −0.5 | Respons tidak dikenali |
| SERVER_ERROR | −1.5 | Server error |
| WAF_BLOCKED | −2 | WAF blokir total |
| STAGNANT | −3 | Modifikasi tidak mengubah apa-apa |

**Bonus PBRS (Potential-Based Reward Shaping):**
Selain nilai di atas, agen juga mendapat **bonus kecil** setiap kali berhasil "mematikan" satu aturan WAF — meski belum bypass penuh. Ini seperti memberikan petunjuk arah agar agen tidak harus menebak-nebak dari awal.

> Mengapa STAGNANT paling rendah? Supaya agen tidak malas memilih aksi yang tidak melakukan apa-apa.

---

## Tiga algoritma yang dibandingkan

Penelitian ini membandingkan tiga cara berbeda agar agen belajar:

### PPO (Proximal Policy Optimization)
- Cara kerja: setiap pembaruan kebijakan dibatasi dengan fungsi "clip" — jika perubahan terlalu besar, otomatis dipotong
- Analogi: seperti pelajar yang boleh belajar tapi tidak boleh lompat terlalu jauh dari pemahaman sebelumnya
- Karakteristik: stabil dan populer, cocok untuk banyak masalah

### TRPO (Trust Region Policy Optimization)
- Cara kerja: pembaruan kebijakan dibatasi secara matematis agar perbedaan antara kebijakan lama dan baru tidak terlalu besar (diukur dengan KL-divergence)
- Analogi: seperti pelajar yang punya aturan keras — "kamu hanya boleh berubah sebesar ini per sesi belajar"
- Karakteristik: lebih konservatif, memberikan jaminan matematis tidak memburuk

### A2C (Advantage Actor-Critic)
- Cara kerja: tidak ada pembatasan khusus — gradien langsung diterapkan setiap langkah
- Analogi: seperti pelajar yang belajar sangat agresif tanpa aturan
- Karakteristik: paling sederhana dan cepat, tapi paling rentan terhadap instabilitas

---

## Eksperimen: bagaimana pengujiannya?

- **WAF yang diuji:** ModSecurity CRS v3.3.2 (sistem keamanan nyata, berjalan di server lokal)
- **Payload:** 108 perintah SQL yang sudah divalidasi (semuanya benar-benar bisa mengambil data)
- **Tiga tingkat kesulitan:**
  - **Trivial (36 payload):** hanya perlu ubah huruf dan spasi
  - **Medium (36 payload):** plus harus melewati aturan fungsi agregat (GROUP_CONCAT)
  - **Complex (36 payload):** plus aturan hex encoding DAN referensi tabel langsung
- **Training:** 150.000 langkah per algoritma
- **Evaluasi:** setiap payload diuji, maksimal 15 langkah modifikasi

---

## Hasil: siapa yang paling bagus?

### Metrik yang digunakan:
- **IFNR** = berapa persen payload yang berhasil di-bypass (makin tinggi makin baik)
- **SPBARC** = rata-rata permintaan HTTP per keberhasilan (makin kecil makin efisien)

### Hasil keseluruhan:

| Algoritma | IFNR | SPBARC | Trivial | Medium | Complex |
|-----------|------|--------|---------|--------|---------|
| **TRPO** | **99.1%** | **6.07** | 100% | 100% | **97.2%** |
| PPO | 88.9% | 6.89 | 100% | 100% | 66.7% |
| A2C | 76.9% | 10.08 | 100% | 97.2% | 33.3% |
| Acak (baseline) | 3.7% | 216 | — | — | — |

**Kesimpulan RQ1:** TRPO terbaik di semua metrik. Perbedaan paling tajam ada di tier **Complex** — di sinilah rantai mutasi panjang benar-benar dibutuhkan, dan TRPO terbukti paling mampu menemukannya.

---

## Temuan Orisinal: Urutan Mutasi Berpengaruh!

Ini adalah temuan yang belum pernah diteliti sebelumnya di bidang ini.

**Pertanyaan:** apakah urutan modifikasi penting? Apakah A lalu B berbeda dengan B lalu A?

**Cara analisis:** untuk setiap pasang modifikasi (A→B), bandingkan tingkat keberhasilan dengan kebalikannya (B→A). Jika perbedaannya lebih dari 10%, pasang ini dianggap "bergantung pada urutan."

**Hasilnya:**
- TRPO: 68 pasang bergantung urutan (dari 1.207 pasang yang dianalisis)
- PPO: 146 pasang bergantung urutan
- A2C: 137 pasang bergantung urutan
- **35 pasang konsensus** — bergantung urutan di minimal 2 dari 3 algoritma

**Contoh paling ekstrem:**
`ident_backtick → hex_to_char`
- Urutan benar (ident_backtick dulu): **98% berhasil**
- Urutan terbalik (hex_to_char dulu): **0% berhasil**

Kenapa? Karena hex_to_char mengubah struktur token identifier — jika dilakukan sebelum ident_backtick, maka backtick tidak bisa diterapkan dengan benar.

**Makna temuan ini:** pola urutan ini SAMA di ketiga algoritma yang berbeda → urutan berasal dari **struktur aturan WAF itu sendiri**, bukan dari cara belajar agen.

---

## Keterbatasan penelitian

1. Hanya menguji satu WAF (ModSecurity) — belum tentu berlaku untuk WAF lain
2. Hanya union-based SQL injection — tipe lain belum diteliti
3. Hanya satu injection point di satu aplikasi (sqli-labs Less-1)

---

## Rencana ke depan

1. **Transfer ke Safeline CE:** WAF berbasis ML (neural network) — apakah kebijakan yang dipelajari di ModSecurity langsung bekerja tanpa training ulang?
2. **Corpus error-based:** 216 payload (union + error)
3. **Tipe injeksi lain:** XSS, second-order SQLi
