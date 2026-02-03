from django.contrib import admin

from .models import Producto


@admin.register(Producto)
class ProductoAdmin(admin.ModelAdmin):
	list_display = ("id", "nombre", "precio")
	search_fields = ("nombre",)
