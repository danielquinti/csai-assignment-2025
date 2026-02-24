"""
Vistas HTML para el catálogo de productos.

Seguridad:
- Todas las vistas requieren autenticación (@login_required).
- Las acciones de escritura requieren rol admin (@admin_required).
- Los datos se validan a través de Django Forms (nunca request.POST directo).
- Las consultas usan exclusivamente el ORM de Django (cero SQL crudo).
- Los clientes solo ven los productos asociados a su usuario.
"""

from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render

from .decorators import admin_required
from .forms import LoginForm, ProductoForm
from .models import Producto


def login_view(request):
    """Pantalla de inicio de sesión."""
    if request.user.is_authenticated:
        return redirect("producto_list")

    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect("producto_list")
    else:
        form = LoginForm(request)

    return render(request, "core/login.html", {"form": form})


@login_required
def logout_view(request):
    """Cierra la sesión del usuario."""
    logout(request)
    return redirect("login")


@login_required
def producto_list_view(request):
    """
    Lista de productos.
    - Admin: ve todos los productos.
    - Cliente: solo ve los productos asociados a su usuario.
    """
    if request.user.es_admin:
        productos = Producto.objects.select_related("usuario").all()
    else:
        productos = Producto.objects.filter(usuario=request.user)

    return render(
        request,
        "core/producto_list.html",
        {"productos": productos, "es_admin": request.user.es_admin},
    )


@login_required
@admin_required
def producto_create_view(request):
    """Formulario de creación de producto (solo admin)."""
    if request.method == "POST":
        form = ProductoForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("producto_list")
    else:
        form = ProductoForm()

    return render(request, "core/producto_form.html", {"form": form, "titulo": "Crear Producto"})


@login_required
@admin_required
def producto_edit_view(request, pk):
    """Formulario de edición de producto (solo admin)."""
    producto = get_object_or_404(Producto, pk=pk)

    if request.method == "POST":
        form = ProductoForm(request.POST, instance=producto)
        if form.is_valid():
            form.save()
            return redirect("producto_list")
    else:
        form = ProductoForm(instance=producto)

    return render(
        request,
        "core/producto_form.html",
        {"form": form, "titulo": "Editar Producto", "producto": producto},
    )


@login_required
@admin_required
def producto_delete_view(request, pk):
    """Confirmación y eliminación de producto (solo admin)."""
    producto = get_object_or_404(Producto, pk=pk)

    if request.method == "POST":
        producto.delete()
        return redirect("producto_list")

    return render(
        request,
        "core/producto_confirm_delete.html",
        {"producto": producto},
    )
