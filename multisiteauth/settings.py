from django.conf import settings

HTTP_AUTH_ENABLED = getattr(settings, 'BASIC_HTTP_AUTH_ENABLED', False)
HTTP_AUTH_GENERAL_USERNAME = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_USERNAME', '')
HTTP_AUTH_GENERAL_PASS = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_PASS', '')
HTTP_AUTH_ALLOW_ADMIN = getattr(settings, 'BASIC_HTTP_AUTH_ALLOW_ADMIN', True)
HTTP_AUTH_REALM = getattr(settings, 'BASIC_HTTP_AUTH_REALM', '')
