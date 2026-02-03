from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from .models import Producto

def home(request: HttpRequest) -> HttpResponse:
	if request.user.is_authenticated:
		return redirect("productos_list")
	return redirect("login")


@login_required
def productos_list(request: HttpRequest) -> HttpResponse:
	productos = Producto.objects.all().order_by("id")
	return render(request, "productos/list.html", {"productos": productos})


@login_required
def producto_detail(request: HttpRequest, pk: int) -> HttpResponse:
	producto = get_object_or_404(Producto, pk=pk)
	return render(request, "productos/detail.html", {"producto": producto})
