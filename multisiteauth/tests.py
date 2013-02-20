import base64
from django.core.urlresolvers import reverse

from django.test import TestCase
from django.test.client import Client

from multisiteauth import settings as local_settings


class CheckAuthenticationTestCase(TestCase):
    fixtures = ['siteauth.json']

    def setUp(self):
        self.client = Client(HTTP_HOST="test-site1.local.org")
        self.clientTwo = Client(HTTP_HOST="test-site2.local.org")
        local_settings.HTTP_AUTH_ENABLED = True
        local_settings.HTTP_AUTH_GENERAL_USERNAME = 'user'
        local_settings.HTTP_AUTH_GENERAL_PASS = "pass"

        local_settings.HTTP_AUTH_REALM = ''

    def testAuthRequest(self):
        response = self.client.get('/', {})
        self.assertEquals(response.status_code, 401, "Authentication was not requested for Site 1")
        response = self.clientTwo.get('/', {})
        self.assertNotEqual(response.status_code, 401, "Authentication was requested for Site 2")

    def testAuthLogin(self):
        encoded_auth = base64.b64encode(local_settings.HTTP_AUTH_GENERAL_USERNAME + ":" +
                                        local_settings.HTTP_AUTH_GENERAL_PASS)
        response = self.client.get('/', **{'HTTP_AUTHORIZATION': "Basic " + encoded_auth})
        self.assertNotEqual(response.status_code, 401, "Not authenticated as test user for Site 1")

    def testBypassAdminAuthenticatedUsers(self):
        allow_admin = local_settings.HTTP_AUTH_ALLOW_ADMIN
        local_settings.HTTP_AUTH_ALLOW_ADMIN = True
        if self.client.login(username="user", password="password"):
            response = self.client.get('/', {})
            self.assertNotEquals(response.status_code, 401, "Authentication was requested for authenticated user.")
            self.client.logout()
            response = self.client.get('/', {})
            self.assertEquals(response.status_code, 401, "Authentication was not requested for Anonymous user.")
        else:
            self.assertTrue(False, "Check the fixture. Could not login to admin with 'user:password' dummy credentials")
        local_settings.HTTP_AUTH_ALLOW_ADMIN = allow_admin

    def testNoBypassAdminAuthenticatedUsers(self):
        allow_admin = local_settings.HTTP_AUTH_ALLOW_ADMIN
        local_settings.HTTP_AUTH_ALLOW_ADMIN = False
        response = self.client.get(reverse('admin:index'), {})
        self.assertEquals(response.status_code, 401, "Authentication was not requested for admin (admin bypass off).")
        local_settings.HTTP_AUTH_ALLOW_ADMIN = allow_admin


    def tearDown(self):
        self.client = None
        self.clientTwo = None
