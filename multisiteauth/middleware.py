from __future__ import unicode_literals
import base64
import logging
import re

from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.core.exceptions import MiddlewareNotUsed
from django.utils.module_loading import import_string

from multisiteauth import settings as local_settings


logger = logging.getLogger(__name__)


def get_custom_site_checker():
    if local_settings.HTTP_AUTH_IS_SITE_PROTECTED:
        try:
            return import_string(local_settings.HTTP_AUTH_IS_SITE_PROTECTED)
        except ImportError:
            logger.warning('Could not import %s. Defaulting to standard check mechanism',
                           local_settings.HTTP_AUTH_IS_SITE_PROTECTED)
            return None


class BasicAuthProtectionMiddleware(object):
    """
    Some middleware to authenticate requests.
    """

    def __init__(self):
        # we'll never get into process request in case HTTP_AUTH is disabled
        if not local_settings.HTTP_AUTH_ENABLED:
            msg = "Basic authentication is not used, this removes it from middleware"
            raise MiddlewareNotUsed(msg)
            # if looking only for blocking access for bad-behaved crawlers SSL is not required
            # BEWARE: without encryption the basic auth credentials are sent in plain text
            #self.basic_auth_requires_ssl = getattr(settings, 'BASIC_HTTP_AUTH_USE_SSL', '')

        self.exception_patterns = [
            re.compile(exception_pattern) for exception_pattern
            in local_settings.HTTP_AUTH_URL_EXCEPTIONS
        ]
        logger.debug("Using %s URLs for basic auth exceptions",
                     local_settings.HTTP_AUTH_URL_EXCEPTIONS)
        self.site_checker = get_custom_site_checker()


    def process_request(self, request):
        # adapted from https://github.com/amrox/django-moat/blob/master/moat/middleware.py
        current_site = local_settings.get_current_site(request)
        if self.is_auth_enabled_for_site(current_site):
            # check if we are already authenticated
            if request.session.get('basicauth_username'):
                logger.debug("Already authenticated as: %s",
                             request.session.get('basicauth_username'))
                return None
            else:
                logger.debug("Could not find basic auth user in session")

            if local_settings.HTTP_AUTH_ALLOW_ADMIN \
               and (request.path.startswith(reverse('admin:index')) \
                    or request.user.is_authenticated()):
                return None

            if self._matches_url_exceptions(request.path):
                return None

            # Check for "cloud" HTTPS environments
            # adapted from http://djangosnippets.org/snippets/2472/
            if 'HTTP_X_FORWARDED_PROTO' in request.META:
                if request.META['HTTP_X_FORWARDED_PROTO'] == 'https':
                    request.is_secure = lambda: True

            return self._http_auth_helper(request)
        return None

    def is_auth_enabled_for_site(self, site):
        if self.site_checker:
            return self.site_checker(site)
        if hasattr(site, 'siteauthorizationstatus'):
            auth_status = getattr(site, 'siteauthorizationstatus', None)
            return auth_status and auth_status.require_basic_authentication
        return False

    def _matches_url_exceptions(self, request_path):
        if not self.exception_patterns:
            return False
        for exception_pattern in self.exception_patterns:
            if exception_pattern.match(request_path):
                logger.debug("Request path %s matches excepted pattern: %s",
                             request_path, exception_pattern)
                return True
        logger.debug("Request %s does not match any excepted URL", request_path)
        return False

    def _http_auth_helper(self, request):
        # At this point, the user is either not logged in, or must log in using
        # http auth.  If they have a header that indicates a login attempt, then
        # use this to try to login.
        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2:
                if auth[0].lower() == 'basic':
                    # Currently, only basic http auth is used.
                    auth_content = auth[1].encode('ascii')
                    decoded_content = base64.b64decode(auth_content).decode('ascii')
                    username, password = decoded_content.split(':')
                    if username == local_settings.HTTP_AUTH_GENERAL_USERNAME and \
                                    password == local_settings.HTTP_AUTH_GENERAL_PASS:
                        request.session['basicauth_username'] = username
                        return None

        # The username/password combo was incorrect, or not logprovided.
        # Challenge the user for a username/password.
        resp = HttpResponse()
        resp.status_code = 401
        try:
            # If we have a realm in our settings, use this for the challenge.
            realm = local_settings.HTTP_AUTH_REALM
        except AttributeError:
            realm = ""

        resp['WWW-Authenticate'] = 'Basic realm="%s"' % realm
        return resp
