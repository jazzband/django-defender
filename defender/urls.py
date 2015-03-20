from django.conf.urls import patterns, url
from .views import block_view, unblock_ip_view, unblock_username_view

urlpatterns = patterns(
    '',
    url(r'^blocks/$', block_view,
        name="defender_blocks_view"),
    url(r'^blocks/ip/(?P<ip_address>[a-z0-9-._]+)/unblock$', unblock_ip_view,
        name="defender_unblock_ip_view"),
    url(r'^blocks/username/(?P<username>[a-z0-9-._@]+)/unblock$',
        unblock_username_view,
        name="defender_unblock_username_view"),
)
