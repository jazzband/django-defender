from django.conf.urls import url, include
from django.contrib import admin

from .urls import urlpatterns as original_urlpatterns

urlpatterns = [
    url(r'^admin/', admin.site.urls),
] + original_urlpatterns
