#!/bin/bash
set -e

echo "Esperando a que PostgreSQL esté disponible..."
while ! python -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('${POSTGRES_HOST:-db}', ${POSTGRES_PORT:-5432}))
    s.close()
    exit(0)
except Exception:
    exit(1)
" 2>/dev/null; do
    sleep 1
done
echo "PostgreSQL disponible."

echo "Generando migraciones..."
python manage.py makemigrations --noinput

echo "Aplicando migraciones..."
python manage.py migrate --noinput

echo "Cargando datos semilla..."
python manage.py seed_data

echo "Iniciando Gunicorn..."
exec gunicorn catalogo.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile -
