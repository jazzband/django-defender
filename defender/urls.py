from django.urls import path, re_path
from .views import block_view, unblock_ip_view, unblock_username_view

urlpatterns = [
    path("blocks/", block_view, name="defender_blocks_view"),
    re_path(
        "blocks/ip/(?P<ip_address>[A-Za-z0-9-._]+)/unblock",
        unblock_ip_view,
        name="defender_unblock_ip_view",
    ),
    path(
        "blocks/username/<path:username>/unblock",
        unblock_username_view,
        name="defender_unblock_username_view",
    ),
]
