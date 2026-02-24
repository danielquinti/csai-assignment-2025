"""
Decoradores personalizados para control de acceso.
"""

from functools import wraps

from django.http import HttpResponseForbidden, JsonResponse


def admin_required(view_func):
    """
    Decorador que restringe el acceso a usuarios con rol 'admin'.
    Devuelve 403 Forbidden si el usuario no es administrador.
    Debe usarse junto con @login_required.
    """

    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.es_admin:
            return HttpResponseForbidden("No tiene permisos para realizar esta acción.")
        return view_func(request, *args, **kwargs)

    return _wrapped


def api_admin_required(view_func):
    """
    Decorador para vistas API que restringe el acceso a administradores.
    Devuelve JSON con status 403 si el usuario no es admin.
    Debe usarse junto con @login_required.
    """

    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.es_admin:
            return JsonResponse(
                {"error": "No tiene permisos para realizar esta acción."},
                status=403,
            )
        return view_func(request, *args, **kwargs)

    return _wrapped
