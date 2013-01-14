from django.conf import settings
from django.http import HttpResponse, get_host
from django.core.urlresolvers import resolve
from django.contrib.sites.models import Site

import base64
import logging

class BasicAuthProtectionMiddleware(object):
    """
    Some middleware to authenticate requests.
    """
    def __init__(self):
        self.basic_auth_enabled = getattr(settings, 'BASIC_HTTP_AUTH_ENABLED', False)
        self.basic_auth_username = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_USERNAME', '')
        self.basic_auth_password = getattr(settings, 'BASIC_HTTP_AUTH_GENERAL_PASS', '')
        # if looking only for blocking access for bad-behaved crawlers SSL is not required
        # BEWARE: without encryption the basic auth credentials are sent in plain text
        #self.basic_auth_requires_ssl = getattr(settings, 'BASIC_HTTP_AUTH_USE_SSL', '')
        self.whitelisted_views = set(getattr(settings, 'BASIC_HTTP_AUTH_BYPASSED_VIEWS', []))
        self.allow_admin = getattr(settings, 'BASIC_HTTP_AUTH_ALLOW_ADMIN', True)

    def process_request(self, request):
        # adapted from https://github.com/amrox/django-moat/blob/master/moat/middleware.py
        # check if it's globally disabled
        if self.basic_auth_enabled:
            current_site = Site.objects.get(domain=get_host(request))
            if hasattr(current_site, 'siteauthorizationstatus'):
                auth_status = getattr(Site.objects.get(domain=get_host(request)), 'siteauthorizationstatus', None)
                if auth_status and auth_status.require_basic_authentication:
                    # check if we are already authenticated
                    if request.session.get('basicauth_username') != None:
                        logging.info("Already authenticated as: " + request.session.get('basicauth_username'))
                        return None
                    else:
                        logging.debug("Could not find basic auth user in session")

                    view_func = resolve(request.META.get('PATH_INFO')).func
                    full_view_name = '%s.%s' % (view_func.__module__, view_func.__name__)
                    #if our view needs to bypass auth, then we just continue.
                    # if it's not whitelisted we need to ask for credentials
                    if full_view_name in self.whitelisted_views:
                        return None
                    if self.allow_admin and view_func.__module__.startswith('django.contrib.admin'):
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