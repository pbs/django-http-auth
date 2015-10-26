from django.db import models
from django.contrib.sites.models import Site


class SiteAuthorizationStatus(models.Model):
    site = models.OneToOneField(Site)
    require_basic_authentication = models.BooleanField(
        verbose_name="Check to add password protection to this site.",
        default=False,
        blank=True
    )

    class Meta:
        verbose_name = "Site Authorization Status"
        verbose_name_plural = verbose_name
