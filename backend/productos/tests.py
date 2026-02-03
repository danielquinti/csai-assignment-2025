from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .models import Producto

class ProductosApiPermissionsTests(TestCase):
	def setUp(self):
		self.client_api = APIClient()
		self.producto = Producto.objects.create(
			nombre="Teclado",
			precio="29.99",
			descripcion="Mecánico",
		)

		user_model = get_user_model()
		self.user = user_model.objects.create_user(username="cliente", password="cliente")
		self.admin = user_model.objects.create_user(
			username="admin2",
			password="admin2",
			is_staff=True,
			is_superuser=True,
		)

	def test_anon_no_puede_listar(self):
		r = self.client_api.get("/api/productos")
		self.assertIn(r.status_code, (401, 403))

	def test_cliente_puede_listar_y_ver_detalle(self):
		self.client_api.force_authenticate(user=self.user)
		r1 = self.client_api.get("/api/productos")
		self.assertEqual(r1.status_code, 200)

		r2 = self.client_api.get(f"/api/productos/{self.producto.id}")
		self.assertEqual(r2.status_code, 200)

	def test_cliente_no_puede_crear(self):
		self.client_api.force_authenticate(user=self.user)
		r = self.client_api.post(
			"/api/productos",
			{"nombre": "Ratón", "precio": "19.99", "descripcion": "Óptico"},
			format="json",
		)
		self.assertEqual(r.status_code, 403)

	def test_admin_puede_crear(self):
		self.client_api.force_authenticate(user=self.admin)
		r = self.client_api.post(
			"/api/productos",
			{"nombre": "Ratón", "precio": "19.99", "descripcion": "Óptico"},
			format="json",
		)
		self.assertEqual(r.status_code, 201)
