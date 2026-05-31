#!/bin/bash

echo "=========================================="
echo "  SQLi Lab - Portable Docker Environment"
echo "=========================================="
echo ""

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker tidak terinstall. Install Docker terlebih dahulu."
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose tidak terinstall. Install Docker Compose terlebih dahulu."
    exit 1
fi

echo "✅ Docker dan Docker Compose terdeteksi"
echo ""

# Start the lab
echo "🚀 Starting SQLi Lab..."
docker-compose up -d

echo ""
echo "⏳ Menunggu services siap..."
sleep 5

# Check if containers are running
if [ "$(docker ps -q -f name=sqlilab-nginx)" ] && [ "$(docker ps -q -f name=sqlilab-app)" ] && [ "$(docker ps -q -f name=sqlilab-mysql)" ]; then
    echo ""
    echo "=========================================="
    echo "✅ SQLi Lab berhasil dijalankan!"
    echo "=========================================="
    echo ""
    echo "📍 Akses lab di: http://localhost:8080"
    echo ""
    echo "🔧 Perintah berguna:"
    echo "  - Stop lab:        docker-compose down"
    echo "  - Lihat logs:      docker-compose logs -f"
    echo "  - Restart nginx:   docker-compose restart nginx"
    echo ""
    echo "📚 Baca README.md untuk dokumentasi lengkap"
    echo "=========================================="
else
    echo ""
    echo "⚠️  Ada masalah saat start containers"
    echo "Cek logs dengan: docker-compose logs"
fi
