# CSAI Assignment 2025

Backend en Django + PostgreSQL (vía Docker) y frontend básico (HTML) para un catálogo de productos.

## Requisitos
- Docker Desktop (recomendado)
- Alternativa local: Python 3 + PostgreSQL

## Arranque rápido (Docker)
Desde la raíz del repo:

```bash
docker-compose up --build
```

- El contenedor `web` ejecuta `migrate` automáticamente y arranca Django.
- La base de datos es PostgreSQL en el contenedor `db`.

### Configuración (Docker)
Docker Compose lee variables desde [backend/.env.docker](backend/.env.docker).

Valores relevantes:
- `DATABASE_URL=postgresql://csai:csai@db:5432/csai`
- Bootstrap de usuarios:
  - `BOOTSTRAP_USER_USERNAME=user`
  - `BOOTSTRAP_USER_PASSWORD=user`
  - `BOOTSTRAP_ADMIN_USERNAME=admin`
  - `BOOTSTRAP_ADMIN_PASSWORD=sk3213r`

Nota: `DJANGO_SECRET_KEY` en Docker es solo para desarrollo local; cámbiala si lo reutilizas.

## Visitar la web
- Login: `http://localhost:8000/login/`
- Catálogo: `http://localhost:8000/productos`
- Admin Django: `http://localhost:8000/admin/`

## API
Base: `http://localhost:8000/api`

- `GET /api/productos` (cliente/admin)
- `GET /api/productos/<id>` (cliente/admin)
- `POST /api/productos` (solo admin)
- `PUT /api/productos/<id>` (solo admin)
- `DELETE /api/productos/<id>` (solo admin)

Autenticación: sesión (login web) o Basic Auth. Por defecto, cualquier endpoint requiere usuario autenticado.

## Desarrollo local (sin Docker)
1) Crea `.env` en `backend/` (ver [backend/.env.example](backend/.env.example))
2) Instala deps:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3) Ejecuta:

```bash
cd backend
python manage.py migrate
python manage.py runserver
```

## Seguridad (resumen)
- Sin SQL crudo: ORM de Django
- Validación: DRF Serializers
- Auth estándar: modelo `User` de Django
- XSS: templates con autoescape (sin `|safe`)
- SSRF: no hay funcionalidad de fetch remoto; evitar introducirla sin allowlist
