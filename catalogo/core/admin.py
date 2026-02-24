from django.contrib import admin

from .models import Producto, Usuario


@admin.register(Usuario)
class UsuarioAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "rol", "is_active")
    list_filter = ("rol", "is_active")
    search_fields = ("username", "email")


@admin.register(Producto)
class ProductoAdmin(admin.ModelAdmin):
    list_display = ("id", "nombre", "precio", "usuario")
    list_filter = ("usuario",)
    search_fields = ("nombre", "descripcion")
