"""
Vistas REST API para el catálogo de productos.

Endpoints:
    GET    /api/productos/        → Lista de productos (filtrada por rol)
    GET    /api/productos/<id>/   → Detalle de un producto
    POST   /api/productos/        → Crear producto (solo admin)
    PUT    /api/productos/<id>/   → Actualizar producto (solo admin)
    DELETE /api/productos/<id>/   → Eliminar producto (solo admin)

Seguridad:
- Autenticación requerida en todos los endpoints.
- Operaciones de escritura restringidas a rol admin (403 para clientes).
- Validación de datos mediante Django Forms (nunca request.POST directo).
- Consultas exclusivamente a través del ORM (cero SQL crudo).
- Los clientes solo acceden a productos asociados a su usuario.
"""

import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_http_methods

from .decorators import api_admin_required
from .forms import ProductoForm
from .models import Producto, Usuario


def _producto_to_dict(producto):
    """Serializa un producto a diccionario (sin SQL crudo)."""
    return {
        "id": producto.id,
        "nombre": producto.nombre,
        "precio": str(producto.precio),
        "descripcion": producto.descripcion,
        "usuario_id": producto.usuario_id,
    }


@login_required
@require_http_methods(["GET"])
def api_producto_list(request):
    """
    GET /api/productos/
    Admin: devuelve todos los productos.
    Cliente: solo devuelve los productos de su usuario.
    """
    if request.user.es_admin:
        productos = Producto.objects.select_related("usuario").all()
    else:
        productos = Producto.objects.filter(usuario=request.user)

    data = [_producto_to_dict(p) for p in productos]
    return JsonResponse(data, safe=False, status=200)


@login_required
@require_http_methods(["GET"])
def api_producto_detail(request, pk):
    """
    GET /api/productos/<id>/
    Admin: puede ver cualquier producto.
    Cliente: solo puede ver productos propios.
    """
    if request.user.es_admin:
        producto = get_object_or_404(Producto, pk=pk)
    else:
        producto = get_object_or_404(Producto, pk=pk, usuario=request.user)

    return JsonResponse(_producto_to_dict(producto), status=200)


@login_required
@api_admin_required
@require_http_methods(["POST"])
def api_producto_create(request):
    """
    POST /api/productos/
    Solo admin. Crea un nuevo producto.
    Los datos se validan a través de ProductoForm.
    """
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "JSON inválido."}, status=400)

    form = ProductoForm(body)
    if form.is_valid():
        producto = form.save()
        return JsonResponse(_producto_to_dict(producto), status=201)

    return JsonResponse({"errors": form.errors}, status=400)


@login_required
@api_admin_required
@require_http_methods(["PUT"])
def api_producto_update(request, pk):
    """
    PUT /api/productos/<id>/
    Solo admin. Actualiza un producto existente.
    Los datos se validan a través de ProductoForm.
    """
    producto = get_object_or_404(Producto, pk=pk)

    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "JSON inválido."}, status=400)

    form = ProductoForm(body, instance=producto)
    if form.is_valid():
        producto = form.save()
        return JsonResponse(_producto_to_dict(producto), status=200)

    return JsonResponse({"errors": form.errors}, status=400)


@login_required
@api_admin_required
@require_http_methods(["DELETE"])
def api_producto_delete(request, pk):
    """
    DELETE /api/productos/<id>/
    Solo admin. Elimina un producto.
    """
    producto = get_object_or_404(Producto, pk=pk)
    producto_id = producto.id
    producto.delete()
    return JsonResponse({"mensaje": f"Producto {producto_id} eliminado."}, status=200)
