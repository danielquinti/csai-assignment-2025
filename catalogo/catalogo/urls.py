"""
URLs raíz del proyecto.

Incluye las rutas de la app core (vistas HTML y API REST).
"""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
]
