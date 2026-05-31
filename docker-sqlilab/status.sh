#!/bin/bash

echo "=========================================="
echo "  SQLi Lab - Status Check"
echo "=========================================="
echo ""

# Check if containers are running
if [ "$(docker ps -q -f name=sqlilab-nginx)" ] && [ "$(docker ps -q -f name=sqlilab-app)" ] && [ "$(docker ps -q -f name=sqlilab-mysql)" ]; then
    echo "✅ Status: RUNNING"
    echo ""
    echo "📍 Lab URL: http://localhost:8080"
    echo ""
    echo "🐳 Containers:"
    docker-compose ps
    echo ""
    echo "💾 Database:"
    echo "   Host: localhost:3306 (or mysql from containers)"
    echo "   User: lab"
    echo "   Pass: lab123"
    echo "   DBs: security, challenges"
    echo ""
    echo "📊 Resource Usage:"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" sqlilab-nginx sqlilab-app sqlilab-mysql
else
    echo "❌ Status: NOT RUNNING"
    echo ""
    echo "Start the lab with: ./start.sh"
fi

echo ""
echo "=========================================="
