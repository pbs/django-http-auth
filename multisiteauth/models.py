from django.db import models
from django.contrib.sites.models import Site

class SiteAuthorizationStatus(models.Model):
    site = models.OneToOneField(Site)
    require_basic_authentication = models.BooleanField(verbose_name="Require basic HTTP authorization",
        default=False,
        blank=True
    )
