# Update ModSecurity Rules - Quick Guide

## 📝 Cara Update Custom Rules

### 1. Edit Rules File

Edit file custom rules:
```bash
nano modsecurity/custom-sqli.conf
# atau
vim modsecurity/custom-sqli.conf
```

### 2. Reload Rules

Setelah edit, reload rules dengan salah satu cara:

**Cara 1: Pakai script (recommended)**
```bash
./reload-rules.sh
```

**Cara 2: Manual restart nginx**
```bash
docker-compose restart nginx
```

**Cara 3: Restart semua (jika ada masalah)**
```bash
docker-compose down
docker-compose up -d
```

### 3. Verify Rules Loaded

Cek apakah rules sudah di-load:
```bash
docker-compose logs nginx | grep "ModSecurity-nginx"
```

Output yang benar:
```
ModSecurity-nginx v1.0.4 (rules loaded inline/local/remote: 0/855/0)
```

### 4. Test Rules

Test dengan payload:
```bash
# Normal request (should pass - 200)
curl "http://localhost:8080/Less-1/?id=1"

# SQLi attack (should block - 403)
curl "http://localhost:8080/Less-1/?id=1' OR '1'='1"
```

## 🔧 Troubleshooting

### Rules tidak di-load

Jika setelah restart rules tidak berubah:

1. **Cek syntax error di rules file**
```bash
docker exec sqlilab-nginx nginx -t
```

2. **Lihat error logs**
```bash
docker-compose logs nginx | grep -i error
```

3. **Restart dengan rebuild**
```bash
docker-compose down
docker-compose up -d --force-recreate nginx
```

### Nginx tidak start setelah edit rules

Kemungkinan ada syntax error di rules file:

1. **Cek logs**
```bash
docker-compose logs nginx
```

2. **Restore backup rules**
```bash
cp modsecurity/custom-sqli.conf.bak modsecurity/custom-sqli.conf
docker-compose restart nginx
```

## 📋 Contoh Edit Rules

### Menambah Rule Baru

Edit `modsecurity/custom-sqli.conf`, tambahkan di akhir file:

```apache
# Detect SLEEP function
SecRule ARGS "@rx (?i:sleep\s*\()" \
    "id:9100011,\
    phase:2,\
    block,\
    log,\
    msg:'SQL Injection - SLEEP function detected',\
    severity:'CRITICAL',\
    tag:'attack-sqli'"
```

**Penting:**
- Rule ID harus unique (gunakan 9100011, 9100012, dst)
- Jangan gunakan ID yang sudah ada

### Disable Rule Tertentu

Comment rule dengan `#`:

```apache
# Rule ini di-disable
# SecRule ARGS "@rx (?i:(--|#))" \
#     "id:9100002,\
#     phase:2,\
#     block,\
#     log,\
#     msg:'SQL Injection Attack - SQL Comment Detected',\
#     severity:'WARNING',\
#     tag:'attack-sqli'"
```

### Mengubah Severity

Ubah dari `block` ke `pass` untuk detection only:

```apache
SecRule ARGS "@rx (?i:(--|#))" \
    "id:9100002,\
    phase:2,\
    pass,\
    log,\
    msg:'SQL Injection Attack - SQL Comment Detected',\
    severity:'WARNING',\
    tag:'attack-sqli'"
```

## 🎯 Best Practices

1. **Backup sebelum edit**
```bash
cp modsecurity/custom-sqli.conf modsecurity/custom-sqli.conf.bak
```

2. **Test rules satu per satu**
   - Tambah 1 rule
   - Reload
   - Test
   - Ulangi

3. **Gunakan ID range yang konsisten**
   - Custom rules: 9100001-9100999
   - Jangan gunakan ID < 9100000 (reserved untuk OWASP CRS)

4. **Log semua rules**
   - Selalu gunakan `log` directive
   - Memudahkan debugging

5. **Document rules**
   - Tambahkan comment di atas setiap rule
   - Jelaskan apa yang di-detect

## 📚 Rule Syntax Reference

### Basic Structure
```apache
SecRule VARIABLE "OPERATOR" \
    "id:UNIQUE_ID,\
    phase:PHASE_NUMBER,\
    ACTION,\
    log,\
    msg:'MESSAGE',\
    severity:'LEVEL',\
    tag:'TAG'"
```

### Common Variables
- `ARGS` - Query string parameters
- `ARGS_POST` - POST body parameters
- `REQUEST_HEADERS` - HTTP headers
- `REQUEST_COOKIES` - Cookies
- `REQUEST_URI` - Request URI

### Common Operators
- `@rx` - Regular expression
- `@contains` - String contains
- `@eq` - Equals
- `@gt` - Greater than
- `@lt` - Less than

### Common Actions
- `block` - Block request (403)
- `pass` - Allow but log
- `deny` - Deny with custom status
- `drop` - Drop connection

### Severity Levels
- `CRITICAL` - 2
- `ERROR` - 3
- `WARNING` - 4
- `NOTICE` - 5

## 🔗 Resources

- ModSecurity Reference Manual: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual
- OWASP CRS: https://coreruleset.org/
- Regex Testing: https://regex101.com/

---

**Quick Command Reference:**

```bash
# Edit rules
nano modsecurity/custom-sqli.conf

# Reload rules
./reload-rules.sh

# Test
curl "http://localhost:8080/Less-1/?id=1' OR '1'='1"

# Check logs
docker-compose logs nginx | grep ModSecurity
```
