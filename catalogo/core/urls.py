"""
Rutas de la app core: vistas HTML y endpoints API REST.
"""

from django.urls import path

from . import api_views, views

urlpatterns = [
    # ── Autenticación ──────────────────────────
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    # ── Vistas HTML (catálogo) ─────────────────
    path("", views.producto_list_view, name="home"),
    path("productos/", views.producto_list_view, name="producto_list"),
    path("productos/crear/", views.producto_create_view, name="producto_create"),
    path("productos/<int:pk>/editar/", views.producto_edit_view, name="producto_edit"),
    path("productos/<int:pk>/eliminar/", views.producto_delete_view, name="producto_delete"),
    # ── API REST (/api/productos) ──────────────
    path("api/productos/", api_views.api_producto_list, name="api_producto_list"),
    path("api/productos/<int:pk>/", api_views.api_producto_detail, name="api_producto_detail"),
    path("api/productos/crear/", api_views.api_producto_create, name="api_producto_create"),
    path("api/productos/<int:pk>/actualizar/", api_views.api_producto_update, name="api_producto_update"),
    path("api/productos/<int:pk>/eliminar/", api_views.api_producto_delete, name="api_producto_delete"),
]
