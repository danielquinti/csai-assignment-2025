"""
Formularios Django para validación segura de datos.

Seguridad:
- Nunca se procesa request.POST directamente; siempre se usa un Form.
- El ORM se encarga de las consultas (cero SQL crudo).
- Se validan y limpian todos los campos antes de persistir.
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm

from .models import Producto


class LoginForm(AuthenticationForm):
    """
    Formulario de inicio de sesión.
    Hereda de AuthenticationForm de Django para aprovechar la validación estándar.
    """

    username = forms.CharField(
        label="Nombre de usuario",
        max_length=150,
        widget=forms.TextInput(attrs={"autofocus": True, "autocomplete": "username"}),
    )
    password = forms.CharField(
        label="Contraseña",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class ProductoForm(forms.ModelForm):
    """
    Formulario para crear y editar productos.
    Valida y limpia todos los campos automáticamente a través de ModelForm.
    """

    class Meta:
        model = Producto
        fields = ["nombre", "precio", "descripcion", "usuario"]
        widgets = {
            "nombre": forms.TextInput(attrs={"maxlength": 255}),
            "precio": forms.NumberInput(attrs={"min": "0", "step": "0.01"}),
            "descripcion": forms.Textarea(attrs={"rows": 4}),
        }

    def clean_precio(self):
        precio = self.cleaned_data.get("precio")
        if precio is not None and precio < 0:
            raise forms.ValidationError("El precio no puede ser negativo.")
        return precio

    def clean_nombre(self):
        nombre = self.cleaned_data.get("nombre", "").strip()
        if not nombre:
            raise forms.ValidationError("El nombre no puede estar vacío.")
        return nombre
