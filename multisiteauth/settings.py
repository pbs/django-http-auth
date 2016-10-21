from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string


HTTP_AUTH_ENABLED = getattr(settings, 'BASIC_HTTP_AUTH_ENABLED', False)
HTTP_AUTH_GENERAL_USERNAME = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_USERNAME', '')
HTTP_AUTH_GENERAL_PASS = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_PASS', '')
HTTP_AUTH_ALLOW_ADMIN = getattr(settings, 'BASIC_HTTP_AUTH_ALLOW_ADMIN', True)
HTTP_AUTH_REALM = getattr(settings, 'BASIC_HTTP_AUTH_REALM', '')
HTTP_AUTH_URL_EXCEPTIONS = getattr(settings, 'BASIC_HTTP_AUTH_URL_EXCEPTIONS', [])

"""
Option to set a custom check for determining if a site has http auth enabled.
If set, it overrides the standard check (site.siteauthoriazationstatus.require_basic_authentication).
If set, it must be the full path (string) to a callable that receives a
django.contrib.sites.models.Site and returns True if basic auth is enabled for that site
and False otherwise.
"""
HTTP_AUTH_IS_SITE_PROTECTED = getattr(settings, 'BASIC_HTTP_AUTH_IS_SITE_PROTECTED', None)


HTTP_AUTH_GET_CURRENT_SITE = getattr(
    settings,
    'BASIC_HTTP_AUTH_GET_CURRENT_SITE',
    'django.contrib.sites.shortcuts.get_current_site')

try:
    get_current_site = import_string(HTTP_AUTH_GET_CURRENT_SITE)
except ImportError as exc:
    err_msg = "Cannot import {}! This is used to get the current site.".format(
        HTTP_AUTH_GET_CURRENT_SITE)
    raise ImproperlyConfigured(err_msg)
