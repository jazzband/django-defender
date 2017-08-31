from django.conf.urls import url
from .views import block_view, unblock_ip_view, unblock_username_view

urlpatterns = [
    url(r'^blocks/$', block_view,
        name="defender_blocks_view"),
    url(r'^blocks/ip/(?P<ip_address>[A-Za-z0-9-._]+)/unblock$', unblock_ip_view,
        name="defender_unblock_ip_view"),
    url(r'^blocks/username/(?P<username>[\w]+[^\/]*)/unblock$',
        unblock_username_view,
        name="defender_unblock_username_view"),
]
