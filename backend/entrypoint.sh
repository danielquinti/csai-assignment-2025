#!/bin/sh
set -eu

cd /app

python manage.py migrate --noinput

exec python manage.py runserver 0.0.0.0:8000
