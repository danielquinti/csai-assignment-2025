# Catálogo de Productos – Django Seguro

Aplicación web de catálogo de productos con dos roles (cliente y administrador), construida con Django, PostgreSQL, Gunicorn, Nginx y Docker.

---

## Índice

1. [Requisitos previos](#requisitos-previos)
2. [Configuración del entorno](#configuración-del-entorno)
3. [Ejecución con Docker](#ejecución-con-docker)
4. [Ejecución local (desarrollo)](#ejecución-local-desarrollo)
5. [Usuarios preconfigurados](#usuarios-preconfigurados)
6. [Endpoints de la API](#endpoints-de-la-api)
7. [Roles y permisos](#roles-y-permisos)
8. [Consideraciones de seguridad](#consideraciones-de-seguridad)
9. [Estructura del proyecto](#estructura-del-proyecto)

---

## Requisitos previos

- **Docker** y **Docker Compose** (para despliegue con contenedores)
- **Python 3.11+** (solo si se ejecuta localmente sin Docker)
- **PostgreSQL 15+** (solo si se ejecuta localmente sin Docker)

---

## Configuración del entorno

1. Copiar el archivo de variables de entorno:

   ```bash
   cp .env.example .env
   ```

2. Editar `.env` con valores apropiados para tu entorno. **Es obligatorio** configurar al menos:

   | Variable             | Descripción                              | Ejemplo                        |
   |----------------------|------------------------------------------|--------------------------------|
   | `DJANGO_SECRET_KEY`  | Clave secreta de Django (única y segura) | `una-clave-larga-y-aleatoria`  |
   | `DJANGO_DEBUG`       | Modo depuración (`True` / `False`)       | `False`                        |
   | `DJANGO_ALLOWED_HOSTS` | Hosts permitidos (separados por coma)  | `localhost,127.0.0.1`          |
   | `POSTGRES_DB`        | Nombre de la base de datos               | `catalogo_db`                  |
   | `POSTGRES_USER`      | Usuario de PostgreSQL                    | `catalogo_user`                |
   | `POSTGRES_PASSWORD`  | Contraseña de PostgreSQL                 | `una-contraseña-segura`        |

   > ⚠️ **Nunca** commitear el archivo `.env` al repositorio. Ya está incluido en `.gitignore`.

---

## Ejecución con Docker

```bash
# Construir y levantar los contenedores
docker compose up --build -d

# Ver logs
docker compose logs -f web

# Detener
docker compose down
```

La aplicación estará disponible en **http://localhost**.

El `entrypoint.sh` se encarga automáticamente de:
- Esperar a que PostgreSQL esté listo
- Ejecutar las migraciones
- Cargar los datos semilla (usuarios y productos iniciales)
- Iniciar Gunicorn

---

## Ejecución local (desarrollo)

```bash
# 1. Crear y activar entorno virtual
python3 -m venv venv
source venv/bin/activate

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Configurar variables de entorno
cp .env.example .env
# Editar .env con las credenciales de tu PostgreSQL local

# 4. Aplicar migraciones
cd catalogo
python manage.py migrate

# 5. Cargar datos semilla
python manage.py seed_data

# 6. Ejecutar servidor de desarrollo
python manage.py runserver
```

La aplicación estará en **http://localhost:8000**.

---

## Usuarios preconfigurados

El comando `seed_data` crea dos usuarios iniciales (las credenciales se leen desde variables de entorno):

| Usuario | Contraseña   | Rol          |
|---------|-------------|--------------|
| `user`  | `contraseña` | Cliente      |
| `admin` | `sk3213r`    | Administrador|

> Las contraseñas de los usuarios semilla se configuran mediante las variables `SEED_USER_PASSWORD` y `SEED_ADMIN_PASSWORD` en el archivo `.env`.

---

## Endpoints de la API

Todos los endpoints requieren autenticación (sesión de Django).

| Método | Ruta                               | Rol permitido | Descripción                        |
|--------|-------------------------------------|---------------|------------------------------------|
| GET    | `/api/productos/`                  | Todos         | Lista productos (filtrados por rol)|
| GET    | `/api/productos/<id>/`             | Todos         | Detalle de un producto             |
| POST   | `/api/productos/crear/`            | Solo Admin    | Crea un nuevo producto             |
| PUT    | `/api/productos/<id>/actualizar/`  | Solo Admin    | Actualiza un producto existente    |
| DELETE | `/api/productos/<id>/eliminar/`    | Solo Admin    | Elimina un producto                |

### Ejemplo de body (POST / PUT)

```json
{
  "nombre": "Nuevo producto",
  "precio": "19.99",
  "descripcion": "Descripción del producto",
  "usuario": 1
}
```

### Códigos de respuesta

| Rol     | GET  | POST | PUT  | DELETE |
|---------|------|------|------|--------|
| Cliente | 200  | 403  | 403  | 403    |
| Admin   | 200  | 201  | 200  | 200    |

---

## Roles y permisos

- **Cliente**: solo puede **ver** los productos asociados a su usuario.
- **Administrador**: puede **ver todos** los productos, además de **crear**, **editar** y **eliminar** cualquier producto.

---

## Consideraciones de seguridad

### 1. Cero SQL crudo
Todas las consultas a la base de datos se realizan exclusivamente a través del **ORM de Django**. No hay concatenación de cadenas en consultas ni uso de `raw()`, `extra()`, o `RawSQL`.

### 2. Validación estricta de entrada
Toda la entrada de usuario pasa por **Django Forms** (`ProductoForm`, `LoginForm`). Nunca se accede directamente a `request.POST` para procesar datos.

### 3. Gestión de secretos
- `SECRET_KEY`, credenciales de base de datos y otros secretos se leen desde **variables de entorno** (via `python-dotenv`).
- El archivo `.env` está excluido del control de versiones mediante `.gitignore`.
- Las contraseñas de los usuarios semilla también se configuran por variables de entorno.

### 4. Autenticación estándar de Django
- Se usa un modelo `Usuario` que extiende `AbstractUser` (autenticación nativa de Django).
- Las vistas están protegidas con `@login_required`.
- Las acciones de administrador usan el decorador `@admin_required` personalizado.
- No se ha implementado ningún sistema de autenticación propio.

### 5. Protección contra XSS (Cross-Site Scripting)
- El **autoescapado de templates** de Django está activo por defecto.
- **No se usa `|safe`** en ningún template.
- Se envía la cabecera **Content-Security-Policy** (CSP) en todas las respuestas, restringiendo la carga de scripts y recursos a `'self'`.
- Se envía **X-Content-Type-Options: nosniff** para prevenir MIME-sniffing.

### 6. Protección contra CSRF
- El middleware CSRF de Django está activo.
- Todos los formularios incluyen `{% csrf_token %}`.
- La cookie CSRF tiene el flag `httponly` habilitado.

### 7. Protección contra SQL Injection
- Uso exclusivo del ORM impide cualquier inyección SQL.
- Los formularios validan y limpian los tipos de datos antes de que lleguen al ORM.

### 8. Protección contra SSRF (Server-Side Request Forgery)
- La aplicación **no realiza peticiones HTTP del lado del servidor** basadas en entrada de usuario, eliminando el vector de ataque SSRF.
- `ALLOWED_HOSTS` está configurado para aceptar solo hosts explícitamente permitidos.
- Nginx está configurado para no seguir redirecciones del upstream (`proxy_redirect off`).

### 9. Principio de mínimo privilegio
- Los campos del modelo usan `blank=False` y `null=False` por defecto.
- Los usuarios cliente no tienen acceso al panel de administración de Django (`is_staff=False`).
- El filtrado de productos a nivel de vista asegura que cada rol solo ve lo que le corresponde.

### 10. Cabeceras de seguridad HTTP
Mediante un middleware personalizado (`SecurityHeadersMiddleware`) y la configuración de Nginx, se envían:
- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` (restringe geolocalización, micrófono, cámara, pagos)

### 11. Configuración de producción
Para despliegue en producción con HTTPS, descomentar en `settings.py`:
```python
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

---

## Estructura del proyecto

```
csai-assignment-2025/
├── .env.example                  # Variables de entorno (plantilla)
├── .gitignore
├── Dockerfile                    # Imagen Docker de la aplicación
├── docker-compose.yml            # Orquestación de servicios
├── entrypoint.sh                 # Script de inicio del contenedor
├── requirements.txt              # Dependencias de Python
├── README.md
├── nginx/
│   └── default.conf              # Configuración de Nginx
├── prompts/                      # Documentación de requisitos
│   ├── attacks.md
│   ├── bd.md
│   ├── domain.md
│   ├── endpoints.md
│   ├── permissions.md
│   └── tech stack.md
└── catalogo/                     # Proyecto Django
    ├── manage.py
    ├── catalogo/
    │   ├── settings.py           # Configuración de Django
    │   ├── urls.py               # URLs raíz
    │   ├── wsgi.py
    │   └── asgi.py
    └── core/                     # Aplicación principal
        ├── models.py             # Modelos: Usuario, Producto
        ├── forms.py              # Formularios de validación
        ├── views.py              # Vistas HTML (templates)
        ├── api_views.py          # Vistas REST API (JSON)
        ├── urls.py               # Rutas de la aplicación
        ├── decorators.py         # Decoradores de permisos
        ├── middleware.py         # Middleware de seguridad
        ├── admin.py              # Registro en Django Admin
        ├── apps.py
        ├── management/
        │   └── commands/
        │       └── seed_data.py  # Comando para datos semilla
        └── templates/
            └── core/
                ├── base.html
                ├── login.html
                ├── producto_list.html
                ├── producto_form.html
                └── producto_confirm_delete.html
```
