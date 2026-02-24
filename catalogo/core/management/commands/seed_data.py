"""
Comando de gestión para poblar la base de datos con datos iniciales.

Crea los usuarios y productos definidos en los requisitos del dominio.
Las credenciales se leen desde variables de entorno para no incluir
secretos en el código fuente.
"""

import os
from decimal import Decimal

from django.core.management.base import BaseCommand

from core.models import Producto, Usuario


class Command(BaseCommand):
    help = "Carga los datos semilla: usuarios y productos iniciales."

    def handle(self, *args, **options):
        self._crear_usuarios()
        self._crear_productos()
        self.stdout.write(self.style.SUCCESS("Datos semilla cargados correctamente."))

    def _crear_usuarios(self):
        """Crea los usuarios base y administrador si no existen."""
        user_username = os.environ.get("SEED_USER_USERNAME", "user")
        user_password = os.environ.get("SEED_USER_PASSWORD", "contraseña")
        user_email = os.environ.get("SEED_USER_EMAIL", "user@example.com")

        admin_username = os.environ.get("SEED_ADMIN_USERNAME", "admin")
        admin_password = os.environ.get("SEED_ADMIN_PASSWORD", "sk3213r")
        admin_email = os.environ.get("SEED_ADMIN_EMAIL", "admin@example.com")

        if not Usuario.objects.filter(username=user_username).exists():
            Usuario.objects.create_user(
                username=user_username,
                email=user_email,
                password=user_password,
                rol=Usuario.Rol.CLIENTE,
            )
            self.stdout.write(f"  Usuario '{user_username}' creado (rol: cliente).")
        else:
            self.stdout.write(f"  Usuario '{user_username}' ya existe, omitido.")

        if not Usuario.objects.filter(username=admin_username).exists():
            Usuario.objects.create_user(
                username=admin_username,
                email=admin_email,
                password=admin_password,
                rol=Usuario.Rol.ADMIN,
                is_staff=True,
            )
            self.stdout.write(f"  Usuario '{admin_username}' creado (rol: admin).")
        else:
            self.stdout.write(f"  Usuario '{admin_username}' ya existe, omitido.")

    def _crear_productos(self):
        """Crea un producto para cada usuario si no existen productos."""
        if Producto.objects.exists():
            self.stdout.write("  Ya existen productos, omitido.")
            return

        user = Usuario.objects.filter(rol=Usuario.Rol.CLIENTE).first()
        admin = Usuario.objects.filter(rol=Usuario.Rol.ADMIN).first()

        if user:
            Producto.objects.create(
                nombre="Producto del Cliente",
                precio=Decimal("29.99"),
                descripcion="Producto de ejemplo asociado al usuario cliente.",
                usuario=user,
            )
            self.stdout.write("  Producto del cliente creado.")

        if admin:
            Producto.objects.create(
                nombre="Producto del Administrador",
                precio=Decimal("49.99"),
                descripcion="Producto de ejemplo asociado al usuario administrador.",
                usuario=admin,
            )
            self.stdout.write("  Producto del administrador creado.")
