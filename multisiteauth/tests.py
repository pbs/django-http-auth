from django.test import TestCase
from django.conf import global_settings
from django.test.client import Client
import settings

# TODO: create fixtures and get request
# TODO: "sneak peek" https://github.com/jsocol/django-waffle/blob/master/waffle/tests/test_templates.py

class CheckAuthenticationTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    def testUserPass(self):
        response = self.client.get('/', {})
        if response.status_code == 200:
            pass
        print response

    def tearDown(self):
        self.client = None



class CheckAdminBypassTestCase(TestCase):
    def setUp(self):
        settings.HTTP_AUTH_ALLOW_ADMIN = True

    def tearDown(self):
        pass

    def test_bypass_admin(self):
        #TODO: get all admin urls - issue: how do i know what are all the urls?


        #TODO: foreach admin url check if auth is required
        pass