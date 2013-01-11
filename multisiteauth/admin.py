from django.conf import settings
from django.contrib import admin
from django.contrib.admin.sites import NotRegistered
from django.contrib.sites.models import Site

from models import AuthorizedSite

def _get_registered_modeladmin(model):
    """ This is a huge hack to get the registered modeladmin for the model.
        We need this functionality in case someone else already registered
        a different modeladmin for this model. """
    return type(admin.site._registry[model])

RegisteredSiteAdmin = _get_registered_modeladmin(Site)
SiteAdminForm = RegisteredSiteAdmin.form

class AuthorizationAdminInline(admin.StackedInline):
    model = AuthorizedSite
    can_delete = False
    verbose_name = "Basic HTTP Authentication"

class ExtendedSiteAdmin(RegisteredSiteAdmin):
    inlines = [AuthorizationAdminInline, ]

try:
    admin.site.unregister(Site)
except NotRegistered:
    pass
admin.site.register(Site, ExtendedSiteAdmin)