import base64
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse

from django.test import TestCase
from django.test.client import Client

from multisiteauth import settings as local_settings


class CheckAuthorizationTestCase(TestCase):
    fixtures = ['siteauth.json']

    def setUp(self):
        self.client = Client(HTTP_HOST="test-site1.local.org")
        self.clientTwo = Client(HTTP_HOST="test-site2.local.org")
        local_settings.HTTP_AUTH_ENABLED = True
        local_settings.HTTP_AUTH_GENERAL_USERNAME = 'basic_http_user'
        local_settings.HTTP_AUTH_GENERAL_PASS = "basic_http_pass"
        local_settings.HTTP_AUTH_REALM = ''
        self.adminuser = User.objects.create_superuser(username="user", email="test@test.org", password="password")
        self.adminuser.save()


    def tearDown(self):
        self.client = None
        self.clientTwo = None
        self.adminuser.delete()

    def _auth_encode(self, username, password):
        """helper method to generate auth encoding"""
        return "Basic " + base64.b64encode("%s:%s" % (username, password))


    def testAuthRequest(self):
        response = self.client.get('/', {})
        self.assertEquals(response.status_code, 401, "Authorization was not requested for Site 1")
        response = self.clientTwo.get('/', {})
        self.assertNotEqual(response.status_code, 401, "Authorization was requested for Site 2")

    def testAuthLogin(self):
        response = self.client.get('/', **{'HTTP_AUTHORIZATION': self._auth_encode("basuser", "badpass")})
        self.assertEqual(response.status_code, 401, "Authorized to access Site 1 with wrong credentials")
        response = self.client.get('/',
                                   **{'HTTP_AUTHORIZATION': self._auth_encode(local_settings.HTTP_AUTH_GENERAL_USERNAME,
                                                                              local_settings.HTTP_AUTH_GENERAL_PASS)})
        self.assertNotEqual(response.status_code, 401, "Not authorized to access Site 1 pages for correct credentials")

    def testBypassAdminAuthorizedClients(self):
        allow_admin = local_settings.HTTP_AUTH_ALLOW_ADMIN
        local_settings.HTTP_AUTH_ALLOW_ADMIN = True
        if self.client.login(username="user", password="password"):
            response = self.client.get('/', {})
            self.assertNotEquals(response.status_code, 401, "Authorization was requested for authenticated user.")
            self.client.logout()
            response = self.client.get('/', {})
            self.assertEquals(response.status_code, 401, "Authorization was not requested for Anonymous user.")
        else:
            self.assertTrue(False, "Check the fixture. Could not login to admin with 'user:password' dummy credentials")
        local_settings.HTTP_AUTH_ALLOW_ADMIN = allow_admin

    def testNoBypassAdminAuthorizedClients(self):
        allow_admin = local_settings.HTTP_AUTH_ALLOW_ADMIN
        local_settings.HTTP_AUTH_ALLOW_ADMIN = False
        response = self.client.get(reverse('admin:index'), {})
        self.assertEquals(response.status_code, 401, "Authorization was not requested for admin (admin bypass off).")
        local_settings.HTTP_AUTH_ALLOW_ADMIN = allow_admin


