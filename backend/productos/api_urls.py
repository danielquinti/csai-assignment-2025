from rest_framework.routers import DefaultRouter

from .api_views import ProductoViewSet

router = DefaultRouter(trailing_slash=False)
router.register(r"productos", ProductoViewSet, basename="productos")

urlpatterns = router.urls
