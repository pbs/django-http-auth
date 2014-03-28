import base64
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse

from django.test import TestCase
from django.test.client import Client

from multisiteauth import settings as local_settings


def _auth_encode(username, password):
    """helper method to generate auth encoding"""
    return "Basic " + base64.b64encode("%s:%s" % (username, password))


class CheckSiteRequiresAuthTestCase(TestCase):
    fixtures = ['siteauth.json']

    def setUp(self):
        local_settings.HTTP_AUTH_ENABLED = True
        local_settings.HTTP_AUTH_GENERAL_USERNAME = 'basic_http_user'
        local_settings.HTTP_AUTH_GENERAL_PASS = "basic_http_pass"
        local_settings.HTTP_AUTH_REALM = ''
        self.settings(SITE_ID=1)
        self.client = Client(HTTP_HOST="test-site1.local.org")


    def tearDown(self):
        self.client = None

    def testAuthRequest(self):
        response = self.client.get('/', {})
        self.assertEquals(response.status_code, 401, "Authorization was not requested for Site 1")


    def testAuthLogin(self):
        response = self.client.get('/', **{'HTTP_AUTHORIZATION': _auth_encode("baduser", "badpass")})
        self.assertEqual(response.status_code, 401,
                         "Response status code: %s\nAuthorized to access Site 1 with wrong credentials" \
                         %response.status_code)
        response = self.client.get('/',
                                   **{'HTTP_AUTHORIZATION': _auth_encode(local_settings.HTTP_AUTH_GENERAL_USERNAME,
                                                                         local_settings.HTTP_AUTH_GENERAL_PASS)})
        self.assertNotEqual(response.status_code, 401,
                            "Response status code: %s\nNot authorized to access Site 1 pages for correct credentials" \
                            %response.status_code)


class AdminAuthorizationSiteTestCase(TestCase):
    fixtures = ['siteauth.json']

    def setUp(self):
        local_settings.HTTP_AUTH_ENABLED = True
        local_settings.HTTP_AUTH_GENERAL_USERNAME = 'basic_http_user'
        local_settings.HTTP_AUTH_GENERAL_PASS = "basic_http_pass"
        local_settings.HTTP_AUTH_REALM = ''
        self.settings(SITE_ID=1)
        self.client = Client(HTTP_HOST="test-site1.local.org")
        superuser = User.objects.create_superuser(username="user", email="test@test.org", password="password")
        superuser.save()


    def tearDown(self):
        self.client = None

    def testBypassAdminAuthorizedClients(self):
        with self.settings(HTTP_AUTH_ALLOW_ADMIN=True):
            if self.client.login(username="user", password="password"):
                response = self.client.get('/', {})
                self.assertNotEquals(response.status_code, 401, "Authorization was requested for authenticated user.")
                self.client.logout()
                response = self.client.get('/', {})
                self.assertEquals(response.status_code, 401, "Authorization was not requested for Anonymous user.")
            else:
                self.assertTrue(False,
                                "Check the fixture. Could not login to admin with 'user:password' dummy credentials")

    def testNoBypassAdminAuthorizedClients(self):
        with self.settings(HTTP_AUTH_ALLOW_ADMIN=False):
            allow_admin = local_settings.HTTP_AUTH_ALLOW_ADMIN
            local_settings.HTTP_AUTH_ALLOW_ADMIN = False
            response = self.client.get(reverse('admin:index'), {})
            self.assertEquals(response.status_code, 401,
                              "Authorization was not requested for admin (admin bypass off).")
            local_settings.HTTP_AUTH_ALLOW_ADMIN = allow_admin


class CheckUnauthorizedSiteTestCase(TestCase):
    fixtures = ['siteauth.json']

    def setUp(self):
        local_settings.HTTP_AUTH_ENABLED = True
        local_settings.HTTP_AUTH_GENERAL_USERNAME = 'basic_http_user'
        local_settings.HTTP_AUTH_GENERAL_PASS = "basic_http_pass"
        local_settings.HTTP_AUTH_REALM = ''
        from django.conf import settings
        settings.SITE_ID = 2
        self.client = Client(HTTP_HOST="test-site2.local.org")


    def tearDown(self):
        self.client = None

    def testAuthRequest(self):
        response = self.client.get('/', {})
        self.assertNotEqual(response.status_code, 401, "Authorization was requested for Site 2")


