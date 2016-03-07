from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string


HTTP_AUTH_ENABLED = getattr(settings, 'BASIC_HTTP_AUTH_ENABLED', False)
HTTP_AUTH_GENERAL_USERNAME = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_USERNAME', '')
HTTP_AUTH_GENERAL_PASS = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_PASS', '')
HTTP_AUTH_ALLOW_ADMIN = getattr(settings, 'BASIC_HTTP_AUTH_ALLOW_ADMIN', True)
HTTP_AUTH_REALM = getattr(settings, 'BASIC_HTTP_AUTH_REALM', '')
HTTP_AUTH_URL_EXCEPTIONS = getattr(settings, 'BASIC_HTTP_AUTH_URL_EXCEPTIONS', [])

HTTP_AUTH_GET_CURRENT_SITE = getattr(
    settings,
    'BASIC_HTTP_AUTH_GET_CURRENT_SITE',
    'django.contrib.sites.shortcuts.get_current_site')

try:
    get_current_site = import_string(HTTP_AUTH_GET_CURRENT_SITE)
except ImportError as exc:
    err_msg = "Cannot import {}! This is used to get the current site."
    raise ImproperlyConfigured(err_msg)
