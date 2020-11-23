from django.urls import path
from django.contrib import admin

from .urls import urlpatterns as original_urlpatterns

urlpatterns = [path("admin/", admin.site.urls),] + original_urlpatterns
