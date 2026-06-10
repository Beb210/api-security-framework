#!/bin/bash
# Скрипт ожидания готовности API

URL=$1
TIMEOUT=${2:-180}  # По умолчанию 3 минуты
INTERVAL=5

echo "⏳ Ожидание готовности API: $URL"
echo "⏱️  Таймаут: ${TIMEOUT} секунд"

START_TIME=$SECONDS
while true; do
    ELAPSED=$((SECONDS - START_TIME))
    
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "❌ Таймаут! API не ответил за ${TIMEOUT} секунд"
        exit 1
    fi
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || echo "000")
    
    if [ "$HTTP_CODE" != "000" ]; then
        echo "✅ API готов! (HTTP $HTTP_CODE, прошло ${ELAPSED}с)"
        exit 0
    fi
    
    echo "   ... ожидание (${ELAPSED}с/${TIMEOUT}с), HTTP код: $HTTP_CODE"
    sleep $INTERVAL
done
