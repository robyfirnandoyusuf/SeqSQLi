#!/bin/bash

echo "=========================================="
echo "  Reload ModSecurity Custom Rules"
echo "=========================================="
echo ""

echo "📝 Restarting nginx to reload ModSecurity rules..."
docker-compose restart nginx

echo ""
echo "⏳ Waiting for nginx to be ready..."
sleep 3

echo ""
echo "✅ Checking ModSecurity status..."
docker-compose logs nginx 2>&1 | grep -i "modsecurity-nginx" | tail -1

echo ""
echo "=========================================="
echo "✅ ModSecurity rules reloaded!"
echo "=========================================="
echo ""
echo "💡 Test your new rules with:"
echo "   curl \"http://localhost:8080/Less-1/?id=1' OR '1'='1\""
echo ""
