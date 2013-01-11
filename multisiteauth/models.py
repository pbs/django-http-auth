from django.db import models
from django.contrib.sites.models import Site

class AuthorizedSite(models.Model):
    site = models.OneToOneField(Site)
    use_basic_authentication = models.BooleanField(name="httpauthorization",
        verbose_name="Require basic HTTP authorization",
        default=False,
        blank=True
    )
#    auth_password = models.CharField(max_length=200)
#    auth_username = models.CharField(max_length=200)
