from rest_framework.viewsets import ModelViewSet

from .models import Producto
from .permissions import IsAdminOrReadOnlyAuthenticated
from .serializers import ProductoSerializer


class ProductoViewSet(ModelViewSet):
    queryset = Producto.objects.all().order_by("id")
    serializer_class = ProductoSerializer
    permission_classes = (IsAdminOrReadOnlyAuthenticated,)
