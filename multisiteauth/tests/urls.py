from django.conf.urls import url, include
from django.contrib import admin

from multisiteauth.tests import views

admin.autodiscover()

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^exception/', views.mock_view),
    url(r'^no_exception/', views.mock_view),
]
