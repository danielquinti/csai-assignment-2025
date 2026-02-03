# CSAI Backend (Django)

## Requisitos
- Python 3
- PostgreSQL (recomendado para la entrega)

## Variables de entorno
Copia el ejemplo y rellena valores:

- `cp .env.example .env`

Variables mínimas:
- `DJANGO_SECRET_KEY`
- `DATABASE_URL` (PostgreSQL recomendado)

Bootstrap de usuarios (para cumplir el enunciado sin hardcodear contraseñas en código):
- `DJANGO_BOOTSTRAP_USERS=true`
- `BOOTSTRAP_USER_USERNAME=user`
- `BOOTSTRAP_ADMIN_USERNAME=admin`
- `BOOTSTRAP_USER_PASSWORD=...`
- `BOOTSTRAP_ADMIN_PASSWORD=...`

## Ejecutar
```bash
cd backend
python manage.py migrate
python manage.py runserver
```

## Ejecutar con Docker (PostgreSQL + Django)
Levanta todo con Docker Compose desde la raíz del repo:

```bash
docker-compose up --build
```

Esto usa el fichero de entorno [backend/.env.docker](backend/.env.docker). Si quieres partir de cero, copia [backend/.env.docker.example](backend/.env.docker.example) a `backend/.env.docker`.

Nota: si tu instalación soporta el plugin, también vale `docker compose up --build`.

## Rutas
- UI:
  - `/login/`
  - `/productos`
- API:
  - `GET /api/productos`
  - `GET /api/productos/<id>`
  - `POST /api/productos` (solo admin)
  - `PUT /api/productos/<id>` (solo admin)
  - `DELETE /api/productos/<id>` (solo admin)

## Visitar la web
- Login: `http://localhost:8000/login/`
- Catálogo: `http://localhost:8000/productos`
- Admin Django: `http://localhost:8000/admin/`

## Seguridad
- ORM de Django (sin SQL crudo)
- Validación con DRF Serializers
- Autenticación estándar de Django
- Autoescape en templates (sin `|safe`)
