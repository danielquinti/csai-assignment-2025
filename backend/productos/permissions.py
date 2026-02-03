from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsAdminOrReadOnlyAuthenticated(BasePermission):
    """Requiere autenticación para cualquier acción; solo admin puede escribir."""

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return False
        if request.method in SAFE_METHODS:
            return True
        return bool(user.is_staff or user.is_superuser)
