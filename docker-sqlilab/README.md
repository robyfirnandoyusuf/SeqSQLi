# SQLi Lab - Portable Docker Environment

Lab SQL Injection yang portable dengan nginx, ModSecurity WAF, dan CORS support.

## Komponen

- **SQLi-Labs**: Aplikasi PHP untuk praktik SQL Injection (65+ challenges)
- **MySQL 5.7**: Database server
- **Nginx + ModSecurity**: Web server dengan WAF (Web Application Firewall)
- **OWASP CRS**: Core Rule Set untuk deteksi serangan
- **Custom SQLi Rules**: Rules khusus untuk deteksi SQL Injection
- **PHP-FPM 7.4**: PHP processor
- **CORS**: Cross-Origin Resource Sharing enabled

## Cara Install

### Prerequisites
- Docker
- Docker Compose

### Langkah-langkah

1. **Copy folder `docker-sqlilab`** ke komputer target

2. **Jalankan lab**:
   ```bash
   cd docker-sqlilab
   ./start.sh
   ```
   
   Atau manual:
   ```bash
   docker-compose up -d
   ```

3. **Tunggu beberapa saat** sampai semua container siap (terutama MySQL initialization)

4. **Akses lab** di browser:
   ```
   http://localhost:8080
   ```

## Konfigurasi

### ModSecurity + Custom Rules

ModSecurity sudah aktif dengan:
- **OWASP CRS 4.x**: 856+ rules untuk deteksi serangan umum
- **Custom SQLi Rules**: 10 rules khusus di `/etc/modsecurity/rules/custom-sqli.conf`

Custom rules yang sudah dikonfigurasi:
- **Rule 9100001**: Deteksi UNION, SELECT, INSERT, DELETE, UPDATE
- **Rule 9100002**: Deteksi SQL comments (--, #, /*, */)
- **Rule 9100003**: Deteksi quote-based injection
- **Rule 9100004**: Deteksi time-based blind SQLi (SLEEP, BENCHMARK)
- **Rule 9100005**: Deteksi information_schema queries
- **Rule 9100006**: Deteksi UNION-based injection
- **Rule 9100007**: Deteksi stacked queries
- **Rule 9100008**: Deteksi hex encoding
- **Rule 9100009**: Deteksi dangerous SQL functions (CONCAT, LOAD_FILE)
- **Rule 9100010**: Deteksi boolean-based blind SQLi

Edit `modsecurity/custom-sqli.conf` untuk memodifikasi rules.

### CORS Configuration
CORS sudah dikonfigurasi di `nginx/modsec.conf` dengan:
- Allow all origins (`*`)
- Support untuk GET, POST, PUT, DELETE, OPTIONS
- Preflight request handling

### Database Credentials
- **Host**: mysql (internal) / localhost:3306 (external)
- **User**: lab
- **Password**: lab123
- **Database**: security, challenges
- **Root Password**: root

## Testing ModSecurity

### Test Blocking
```bash
# Akan diblock oleh ModSecurity (403 Forbidden)
curl "http://localhost:8080/Less-1/?id=1' OR '1'='1"
curl "http://localhost:8080/Less-1/?id=1' UNION SELECT 1,2,3--"
curl "http://localhost:8080/Less-1/?id=1--"
curl "http://localhost:8080/Less-1/?id=1' AND 1=2 UNION SELECT 1,table_name,3 FROM information_schema.tables--"
```

### Test Normal Request
```bash
# Normal request (akan berhasil - 200 OK)
curl "http://localhost:8080/Less-1/?id=1"
```

### Lihat ModSecurity Logs
```bash
docker-compose logs nginx | grep ModSecurity
```

## Perintah Berguna

### Start lab
```bash
./start.sh
# atau
docker-compose up -d
```

### Stop lab
```bash
./stop.sh
# atau
docker-compose down
```

### Check status
```bash
./status.sh
# atau
docker-compose ps
```

### Stop dan hapus data
```bash
docker-compose down -v
```

### Lihat logs
```bash
# Semua logs
docker-compose logs -f

# Nginx + ModSecurity logs
docker-compose logs -f nginx

# PHP app logs
docker-compose logs -f php-app

# MySQL logs
docker-compose logs -f mysql
```

### Restart service tertentu
```bash
docker-compose restart nginx
docker-compose restart php-app
```

### Akses container
```bash
# Akses nginx container
docker exec -it sqlilab-nginx sh

# Akses PHP container
docker exec -it sqlilab-app sh

# Akses MySQL container
docker exec -it sqlilab-mysql bash
```

## Troubleshooting

### Port 8080 sudah digunakan
Edit `docker-compose.yml` bagian ports:
```yaml
ports:
  - "8888:8080"  # Ganti 8080 ke port lain
```

### MySQL tidak bisa connect
Tunggu beberapa saat sampai MySQL selesai initialize. Cek dengan:
```bash
docker-compose logs mysql
```

### ModSecurity terlalu strict
Jika ingin disable ModSecurity sementara, edit `docker-compose.yml`:
```yaml
environment:
  - MODSEC_RULE_ENGINE=DetectionOnly  # Hanya log, tidak block
```

Atau disable custom rules dengan comment di `modsecurity/custom-sqli.conf`.

### Normal request di-block
Cek logs untuk melihat rule mana yang trigger:
```bash
docker-compose logs nginx | grep "Access denied"
```

Adjust anomaly score threshold jika perlu (default: 5).

## Struktur Folder

```
docker-sqlilab/
├── docker-compose.yml          # Orchestration file
├── Dockerfile                  # PHP-FPM image
├── README.md                   # Dokumentasi ini
├── QUICKSTART.md              # Quick reference
├── SUMMARY.txt                # Summary lengkap
├── start.sh                   # Start script
├── stop.sh                    # Stop script
├── status.sh                  # Status checker
├── init-challenges-db.sql     # Init script untuk challenges DB
├── sqli-labs/                 # Aplikasi SQLi Labs (65+ challenges)
├── nginx/
│   ├── modsec.conf           # Nginx config dengan ModSecurity
│   ├── simple.conf           # Simple config tanpa ModSecurity
│   └── default.conf          # Backup config
└── modsecurity/
    ├── modsecurity.conf      # ModSecurity main config
    └── custom-sqli.conf      # Custom SQLi detection rules ⭐
```

## Portabilitas

Lab ini sepenuhnya portable. Untuk membawa ke komputer lain:

1. **Copy seluruh folder `docker-sqlilab`** (bisa via USB, cloud, zip, dll)
2. **Pastikan Docker dan Docker Compose terinstall** di komputer target
3. **Jalankan** `./start.sh` atau `docker-compose up -d`

Tidak perlu install PHP, MySQL, nginx, atau ModSecurity secara manual!

## SQLi-Labs Challenges

Lab ini berisi 65+ challenges yang mencakup:
- Error-based SQLi (Less 1-14)
- UNION-based SQLi (Less 1-4)
- Blind SQLi - Boolean (Less 5, 8)
- Blind SQLi - Time-based (Less 9, 10)
- POST-based SQLi (Less 11-17)
- Header-based SQLi (Less 18-21)
- Cookie-based SQLi (Less 20-22)
- Second Order SQLi (Less 24)
- Stacked Queries (Less 38-53)
- WAF Bypass (Less 23-28)
- Advanced Challenges (Less 54-65)

Akses index: http://localhost:8080

## Catatan Keamanan

⚠️ **PENTING**: Lab ini dirancang untuk pembelajaran dan testing. **JANGAN** deploy ke production atau expose ke internet publik karena:
- Aplikasi sengaja vulnerable untuk pembelajaran
- Credentials menggunakan default values
- CORS terbuka untuk semua origin
- ModSecurity bisa di-bypass untuk keperluan testing

## Advanced: Tuning ModSecurity

### Adjust Paranoia Level
Edit `docker-compose.yml`:
```yaml
environment:
  - BLOCKING_PARANOIA=2  # 1-4, semakin tinggi semakin strict
```

### Adjust Anomaly Score
Anomaly scoring: setiap rule yang match menambah score. Jika total score >= threshold, request di-block.

Default threshold: 5 (inbound), 4 (outbound)

Untuk mengubah, tambahkan di `modsecurity/custom-sqli.conf`:
```
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=10"
```

### Whitelist Specific Rules
Untuk disable rule tertentu di path tertentu:
```nginx
location /Less-1/ {
    modsecurity_rules '
        SecRuleRemoveById 9100002
    ';
}
```

## Lisensi

SQLi-Labs adalah project open source oleh Audi-1. Docker setup ini dibuat untuk keperluan edukasi.

## Credits

- SQLi-Labs: https://github.com/Audi-1/sqli-labs
- OWASP ModSecurity CRS: https://coreruleset.org/
- Docker setup: Custom untuk keperluan portable lab
