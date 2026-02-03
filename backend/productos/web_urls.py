from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("productos", views.productos_list, name="productos_list"),
    path("productos/<int:pk>", views.producto_detail, name="producto_detail"),
]
