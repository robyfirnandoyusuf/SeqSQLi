#!/bin/bash

echo "🛑 Stopping SQLi Lab..."
docker-compose down

echo ""
echo "✅ SQLi Lab stopped"
echo ""
echo "💡 Untuk menghapus data juga, jalankan: docker-compose down -v"
