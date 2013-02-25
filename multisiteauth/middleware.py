import base64
import logging
from django.core.urlresolvers import reverse

from django.http import HttpResponse
from django.contrib.sites.models import Site
from django.core.exceptions import MiddlewareNotUsed

from multisiteauth import settings as local_settings


class BasicAuthProtectionMiddleware(object):
    """
    Some middleware to authenticate requests.
    """

    def __init__(self):
        # we'll never get into process request in case HTTP_AUTH is disabled
        if not local_settings.HTTP_AUTH_ENABLED:
            raise MiddlewareNotUsed("Basic authentication is not used, this removes it from middleware")
            # if looking only for blocking access for bad-behaved crawlers SSL is not required
            # BEWARE: without encryption the basic auth credentials are sent in plain text
            #self.basic_auth_requires_ssl = getattr(settings, 'BASIC_HTTP_AUTH_USE_SSL', '')

    def process_request(self, request):
        # adapted from https://github.com/amrox/django-moat/blob/master/moat/middleware.py
        current_site = Site.objects.get_current()
        if hasattr(current_site, 'siteauthorizationstatus'):
            auth_status = getattr(current_site, 'siteauthorizationstatus', None)
            if auth_status and auth_status.require_basic_authentication:
                # check if we are already authenticated
                if request.session.get('basicauth_username'):
                    logging.info("Already authenticated as: " + request.session.get('basicauth_username'))
                    return None
                else:
                    logging.debug("Could not find basic auth user in session")

                if local_settings.HTTP_AUTH_ALLOW_ADMIN \
                    and (request.path.startswith(reverse('admin:index')) \
                             or request.user.is_authenticated()):
                    return None

                # Check for "cloud" HTTPS environments
                # adapted from http://djangosnippets.org/snippets/2472/
                if 'HTTP_X_FORWARDED_PROTO' in request.META:
                    if request.META['HTTP_X_FORWARDED_PROTO'] == 'https':
                        request.is_secure = lambda: True

                return self._http_auth_helper(request)
        return None

    def _http_auth_helper(self, request):
        # At this point, the user is either not logged in, or must log in using
        # http auth.  If they have a header that indicates a login attempt, then
        # use this to try to login.
        if request.META.has_key('HTTP_AUTHORIZATION'):
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2:
                if auth[0].lower() == 'basic':
                    # Currently, only basic http auth is used.
                    username, password = base64.b64decode(auth[1]).split(':')
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