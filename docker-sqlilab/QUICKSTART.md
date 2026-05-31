# SQLi Lab Docker - Quick Reference

## 🚀 Quick Start

```bash
cd docker-sqlilab
./start.sh
```

Akses: **http://localhost:8080**

## 📦 Isi Package

- **SQLi-Labs** - 65+ SQL Injection challenges
- **MySQL 5.7** - Database server
- **Nginx** - Web server dengan CORS
- **PHP-FPM 7.4** - PHP processor

## 🎯 Portable - Bawa Kemana Saja

1. Copy folder `docker-sqlilab`
2. Install Docker + Docker Compose di komputer target
3. Jalankan `./start.sh`

✅ Tidak perlu install PHP, MySQL, atau nginx manual!

## 📝 Perintah Penting

| Perintah | Fungsi |
|----------|--------|
| `./start.sh` | Start lab |
| `./stop.sh` | Stop lab |
| `docker-compose up -d` | Start manual |
| `docker-compose down` | Stop manual |
| `docker-compose down -v` | Stop + hapus data |
| `docker-compose logs -f` | Lihat logs |
| `docker-compose ps` | Status containers |
| `docker-compose restart nginx` | Restart nginx |

## 🧪 Test Lab

```bash
# Normal request
curl "http://localhost:8080/Less-1/?id=1"

# SQLi payload
curl "http://localhost:8080/Less-1/?id=1' OR '1'='1"

# Challenge 2
curl "http://localhost:8080/Less-2/?id=1"
```

## 🌐 Akses dari Browser

```
http://localhost:8080              # Index page
http://localhost:8080/Less-1/      # Challenge 1
http://localhost:8080/Less-2/      # Challenge 2
...
http://localhost:8080/Less-65/     # Challenge 65
```

## ⚙️ Credentials

- **MySQL User**: `lab`
- **MySQL Pass**: `lab123`
- **MySQL Root**: `root`
- **Databases**: `security`, `challenges`
- **MySQL Host**: `mysql` (internal) / `localhost` (external)

## 🔧 Troubleshooting

### Port 8080 sudah dipakai
Edit `docker-compose.yml`:
```yaml
ports:
  - "8888:80"  # Ganti ke port lain
```

### MySQL belum ready
```bash
docker-compose logs mysql
# Tunggu sampai muncul: "ready for connections"
```

### Reset semua
```bash
docker-compose down -v
docker-compose up -d
```

### Container tidak jalan
```bash
docker-compose ps
docker-compose logs <service-name>
```

## 📚 Challenges

SQLi-Labs berisi 65+ challenges:
- ✅ Error-based SQLi
- ✅ UNION-based SQLi  
- ✅ Blind SQLi (Boolean & Time)
- ✅ POST-based SQLi
- ✅ Header-based SQLi
- ✅ Cookie-based SQLi
- ✅ Second Order SQLi
- ✅ Stacked Queries

## 🔒 CORS Enabled

CORS sudah dikonfigurasi untuk:
- Allow all origins (`*`)
- Methods: GET, POST, PUT, DELETE, OPTIONS
- Cocok untuk testing dengan tools/scripts

## 💡 Tips

1. **Backup data**: Sebelum reset, backup database jika perlu
2. **Logs**: Gunakan `docker-compose logs -f` untuk debug
3. **Performance**: Jika lambat, cek resource Docker
4. **Network**: Pastikan port 8080 tidak dipakai aplikasi lain

## ⚠️ Keamanan

**JANGAN** expose ke internet! Lab ini:
- Sengaja vulnerable untuk pembelajaran
- Tidak ada security hardening
- CORS terbuka untuk semua
- Credentials default

Hanya untuk **local testing** dan **pembelajaran**!

## 📖 Dokumentasi Lengkap

Lihat `README.md` untuk:
- Setup detail
- Advanced configuration
- ModSecurity setup (optional)
- Troubleshooting lengkap
- Struktur folder

---

**Happy Hacking! 🎯**
