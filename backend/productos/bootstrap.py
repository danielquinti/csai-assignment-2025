import logging
import os

from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)


def ensure_bootstrap_users() -> None:
    """Crea usuarios iniciales si faltan.

    Por seguridad, las contraseñas se leen de variables de entorno y no se
    embeben en el código.
    """

    if os.environ.get("DJANGO_BOOTSTRAP_USERS", "true").lower() not in {"1", "true", "yes"}:
        return

    user_password = os.environ.get("BOOTSTRAP_USER_PASSWORD")
    admin_password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")

    if not user_password or not admin_password:
        logger.warning(
            "Bootstrap de usuarios omitido: define BOOTSTRAP_USER_PASSWORD y "
            "BOOTSTRAP_ADMIN_PASSWORD para crear 'user' y 'admin'."
        )
        return

    User = get_user_model()

    username_user = os.environ.get("BOOTSTRAP_USER_USERNAME", "user")
    username_admin = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "admin")

    email_user = os.environ.get("BOOTSTRAP_USER_EMAIL", "")
    email_admin = os.environ.get("BOOTSTRAP_ADMIN_EMAIL", "")

    user_obj, created_user = User.objects.get_or_create(
        username=username_user,
        defaults={"email": email_user, "is_staff": False, "is_superuser": False},
    )
    if created_user or not user_obj.has_usable_password():
        user_obj.set_password(user_password)
        user_obj.save(update_fields=["password"])

    admin_obj, created_admin = User.objects.get_or_create(
        username=username_admin,
        defaults={"email": email_admin, "is_staff": True, "is_superuser": True},
    )
    needs_privileges = not (admin_obj.is_staff and admin_obj.is_superuser)
    if needs_privileges:
        admin_obj.is_staff = True
        admin_obj.is_superuser = True

    if created_admin or not admin_obj.has_usable_password() or needs_privileges:
        admin_obj.set_password(admin_password)
        fields = ["password"]
        if needs_privileges:
            fields.extend(["is_staff", "is_superuser"])
        admin_obj.save(update_fields=fields)
