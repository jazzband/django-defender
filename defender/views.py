from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import reverse


from .utils import get_blocked_ips, get_blocked_usernames, unblock_ip, unblock_username


@staff_member_required
def block_view(request):
    """ List the blocked IP and Usernames """
    blocked_ip_list = get_blocked_ips()
    blocked_username_list = get_blocked_usernames()

    context = {
        "blocked_ip_list": blocked_ip_list,
        "blocked_username_list": blocked_username_list,
    }
    return render(request, "defender/admin/blocks.html", context)


@staff_member_required
def unblock_ip_view(request, ip_address):
    """ upblock the given ip """
    if request.method == "POST":
        unblock_ip(ip_address)
    return HttpResponseRedirect(reverse("defender_blocks_view"))


@staff_member_required
def unblock_username_view(request, username):
    """ unblockt he given username """
    if request.method == "POST":
        unblock_username(username)
    return HttpResponseRedirect(reverse("defender_blocks_view"))
