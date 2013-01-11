from django.conf import settings
from django.http import HttpResponse, iri_to_uri, get_host
from django.core.urlresolvers import resolve

import base64
import logging

class HttpResponseTemporaryRedirect(HttpResponse):
    status_code = 307

    def __init__(self, redirect_to):
        HttpResponse.__init__(self)
        self['Location'] = iri_to_uri(redirect_to)

class BasicAuthProtectionMiddleware(object):
    """
    Some middleware to authenticate all requests.
    """
    def __init__(self):
        self.basic_auth_enabled = getattr(settings, 'BASIC_HTTP_AUTH_ENABLED', False)
        self.basic_auth_username = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_USERNAME', '')
        self.basic_auth_password = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_PASS', '')
        # if looking only for blocking access for bad-behaved crawlers SSL is not required
        # without encryption the basic auth credentials are sent in plain sight
        self.basic_http_auth_requires_ssl = getattr(settings, 'BASIC_HTTP_AUTH_USE_SSL', '')

    def process_request(self, request):
        # adapted from https://github.com/amrox/django-moat/blob/master/moat/middleware.py
        # check if it's globally disabled
        if self.basic_auth_enabled:
            # see if we already authenticated
            if request.session.get('basicauth_username') != None:
                logging.info("Already authenticated as: " + request.session.get('basicauth_username'))
                return None
            else:
                logging.debug("Could not find auth user in session")

            view_func = resolve(request.META.get('PATH_INFO')).func
            full_view_name = '%s.%s' % (view_func.__module__, view_func.__name__)
            logging.debug("full_view_name = %s" % (full_view_name))

            # Check for "cloud" HTTPS environments
            # adapted from http://djangosnippets.org/snippets/2472/
            if 'HTTP_X_FORWARDED_PROTO' in request.META:
                if request.META['HTTP_X_FORWARDED_PROTO'] == 'https':
                    request.is_secure = lambda: True

            #if use SSL for authentication, redirect to secure
            if self.basic_http_auth_requires_ssl and not request.is_secure():
                return self._redirect(request)

            return self._http_auth_helper(request)

    def _redirect(self, request):
        newurl = "https://%s%s" % (get_host(request),request.get_full_path())
        if settings.DEBUG and request.method == 'POST':
            raise RuntimeError,\
            """Django can't perform a SSL redirect while maintaining POST data.
            Please structure your views so that redirects only occur during GETs."""

        return HttpResponseTemporaryRedirect(newurl)

    def _http_auth_helper(self, request):
        # At this point, the user is either not logged in, or must log in using
        # http auth.  If they have a header that indicates a login attempt, then
        # use this to try to login.
        if request.META.has_key('HTTP_AUTHORIZATION'):
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2:
                if auth[0].lower() == 'basic':
                    # Currently, only basic http auth is used.
                    uname, passwd = base64.b64decode(auth[1]).split(':')
                    if uname==self.basic_auth_username and passwd == self.basic_auth_password:
                        request.session['basicauth_username'] = uname
                        return None

        # The username/password combo was incorrect, or not provided.
        # Challenge the user for a username/password.
        resp = HttpResponse()
        resp.status_code = 401
        try:
            # If we have a realm in our settings, use this for the challenge.
            realm = settings.HTTP_AUTH_REALM
        except AttributeError:
            realm = ""

        resp['WWW-Authenticate'] = 'Basic realm="%s"' % realm
        return resp