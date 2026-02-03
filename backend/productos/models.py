from django.db import models


class Producto(models.Model):
	nombre = models.CharField(max_length=100)
	precio = models.DecimalField(max_digits=10, decimal_places=2)
	descripcion = models.TextField(blank=True, default="")

	class Meta:
		verbose_name = "producto"
		verbose_name_plural = "productos"

	def __str__(self) -> str:
		return self.nombre
