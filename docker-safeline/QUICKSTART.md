# Safeline CE — Quickstart

## Arsitektur

```
localhost:8080  →  nginx + ModSecurity  →  sqlilab-app   (RQ1 — rule-based WAF)
localhost:8081  →  nginx plain          →  sqlilab-app   (no WAF, ground truth)
localhost:8888  →  Safeline CE          →  nginx-plain   (RQ2 — ML-based WAF)
localhost:9443  →  Safeline UI          →  (konfigurasi)
```

## Prasyarat

sqli-labs harus jalan duluan (Safeline butuh networknya):
```bash
cd docker-sqlilab && docker compose up -d
```

## Setup

### Cara 1 — Official install script (recommended, images selalu up-to-date)

```bash
bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/setup.sh)"
```

Setelah selesai, edit `/data/safeline/.env`:
```
SUBNET_PREFIX=172.23.222   # hindari overlap dengan docker-sqlilab (172.22.0.0/16)
REGION=-g                  # English UI
```

Edit `/data/safeline/docker-compose.yaml` — ubah service `tengine`:
```yaml
# Hapus:   network_mode: host
# Tambah:
extra_hosts:
  - "host.docker.internal:host-gateway"
ports:
  - "8888:8888"
ulimits:
  nofile: 131072
networks:
  safeline-ce:
    ipv4_address: ${SUBNET_PREFIX}.6
```

```bash
cd /data/safeline && docker compose up -d
```

### Cara 2 — Docker Compose dari repo ini

```bash
cp .env.example .env
# Edit .env: ganti POSTGRES_PASSWORD dan pastikan SUBNET_PREFIX tidak overlap
docker compose up -d
```

> Catatan: IMAGE_PREFIX di .env.example pakai Huawei Cloud China.
> Untuk akses lebih cepat dari luar China bisa ganti ke `chaitin/safeline`.

## Konfigurasi site di UI

1. Buka `https://localhost:9443`
2. Ambil password: `docker exec safeline-mgt /app/mgt-cli reset-admin`
3. Login → **Applications → Add**
4. Isi:
   - **Domain**: `Match All Host` (biarkan kosong)
   - **Port**: `8888`
   - **Upstream**: `http://host.docker.internal:8081`
5. Save — Safeline mulai protect sqli-labs via port 8888

## Verifikasi

```bash
# Normal request — harus 200
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8888/Less-1/?id=1"

# SQLi — harus 403
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://localhost:8888/Less-1/?id=1%27%20OR%20%271%27%3D%271%27--%20-"
```

## Troubleshooting

**Network overlap saat `docker compose up`:**
```bash
docker network ls  # cek subnet yang ada
# Edit .env: ganti SUBNET_PREFIX ke range yang bebas (misal 172.24.222)
```

**UI masih bahasa China:**
```
REGION=-g di .env → docker compose pull && docker compose up -d
```

**Port 8888 tidak respond dari Windows browser:**
Pastikan tengine TIDAK pakai `network_mode: host` — gunakan port mapping eksplisit seperti di docker-compose.yml ini.

**Reset password:**
```bash
docker exec safeline-mgt /app/mgt-cli reset-admin
```
