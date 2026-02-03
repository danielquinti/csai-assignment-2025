from django.apps import AppConfig
from django.db.models.signals import post_migrate


class ProductosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'productos'

    def ready(self) -> None:
        from .bootstrap import ensure_bootstrap_users

        post_migrate.connect(
            lambda **kwargs: ensure_bootstrap_users(),
            sender=self,
            dispatch_uid="productos.bootstrap_users",
        )
