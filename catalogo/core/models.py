"""
Modelos del dominio: Usuario y Producto.

Principios de seguridad aplicados:
- blank=False y null=False por defecto (mínimo privilegio).
- Se usa AbstractUser de Django (autenticación estándar).
- Relaciones mediante ForeignKey del ORM (cero SQL crudo).
"""

from django.contrib.auth.models import AbstractUser
from django.db import models


class Usuario(AbstractUser):
    """
    Modelo de usuario extendido con campo de rol.
    Hereda de AbstractUser para aprovechar el sistema de autenticación de Django.
    """

    class Rol(models.TextChoices):
        CLIENTE = "cliente", "Cliente"
        ADMIN = "admin", "Administrador"

    email = models.EmailField("correo electrónico", blank=False)
    rol = models.CharField(
        "rol",
        max_length=10,
        choices=Rol.choices,
        default=Rol.CLIENTE,
    )

    class Meta:
        verbose_name = "usuario"
        verbose_name_plural = "usuarios"

    def __str__(self):
        return self.username

    @property
    def es_admin(self):
        return self.rol == self.Rol.ADMIN


class Producto(models.Model):
    """
    Producto del catálogo.
    Cada producto está asociado a un usuario responsable.
    """

    nombre = models.CharField("nombre", max_length=255)
    precio = models.DecimalField("precio", max_digits=10, decimal_places=2)
    descripcion = models.TextField("descripción")
    usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        related_name="productos",
        verbose_name="usuario responsable",
    )

    class Meta:
        verbose_name = "producto"
        verbose_name_plural = "productos"
        ordering = ["id"]

    def __str__(self):
        return self.nombre
