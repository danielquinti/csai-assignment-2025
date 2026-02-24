"""
Middleware de seguridad personalizado.

Protecciones implementadas:
- Content-Security-Policy (CSP): previene XSS y carga de recursos no autorizados.
- X-Content-Type-Options: previene MIME-sniffing.
- Referrer-Policy: limita la información del referrer.
- Permissions-Policy: restringe APIs del navegador.
- Protección SSRF: no se realizan peticiones HTTP del lado del servidor
  basadas en entrada de usuario. Los hosts permitidos se controlan
  mediante ALLOWED_HOSTS en settings.py.
"""


class SecurityHeadersMiddleware:
    """
    Agrega cabeceras de seguridad HTTP a todas las respuestas.
    Complementa las protecciones nativas de Django (CSRF, XSS filter,
    X-Frame-Options, Clickjacking).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Política de seguridad de contenido – previene XSS
        response["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # Previene MIME-sniffing
        response["X-Content-Type-Options"] = "nosniff"

        # Política de referrer
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restringe APIs del navegador no necesarias
        response["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        return response
