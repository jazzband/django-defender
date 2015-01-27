from django.contrib import admin
from django.conf.urls import patterns, url
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse

from .models import AccessAttempt
from .utils import (
    get_blocked_ips, get_blocked_usernames, unblock_ip, unblock_username)


class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = (
        'attempt_time',
        'ip_address',
        'user_agent',
        'username',
        'path_info',
        'login_valid',
    )

    list_filter = [
        'attempt_time',
        'ip_address',
        'username',
        'path_info',
    ]

    search_fields = [
        'ip_address',
        'username',
        'user_agent',
        'path_info',
    ]

    date_hierarchy = 'attempt_time'

    fieldsets = (
        (None, {
            'fields': ('path_info', 'login_valid')
        }),
        ('Form Data', {
            'fields': ('get_data', 'post_data')
        }),
        ('Meta Data', {
            'fields': ('user_agent', 'ip_address', 'http_accept')
        })
    )

    def get_urls(self):
        """ get the default urls and add ours """
        urls = super(AccessAttemptAdmin, self).get_urls()
        my_urls = patterns(
            '',
            url(r'^blocks/$',
                self.admin_site.admin_view(self.block_view),
                name="defender_blocks_view"),
            url(r'^blocks/ip/(?P<ip>\w+)/unblock$',
                self.admin_site.admin_view(self.unblock_ip_view),
                name="defender_unblock_ip_view"),
            url(r'^blocks/username/(?P<username>\w+)/unblock$',
                self.admin_site.admin_view(self.unblock_username_view),
                name="defender_unblock_username_view"),
        )
        return my_urls + urls

    def block_view(self, request):
        """ List the blocked IP and Usernames """
        blocked_ip_list = get_blocked_ips()
        blocked_username_list = get_blocked_usernames()

        context = {'current_app': self.admin_site.name,
                   'blocked_ip_list': blocked_ip_list,
                   'blocked_username_list': blocked_username_list}
        return render_to_response(
            'admin/defender/blocks.html',
            context, context_instance=RequestContext(request))

    def unblock_ip_view(self, request, ip):
        """ upblock the given ip """
        if request.method == 'POST':
            unblock_ip(ip)
        return HttpResponseRedirect(reverse("defender_blocks_view"))

    def unblock_username_view(self, request, username):
        """ unblockt he given username """
        if request.method == 'POST':
            unblock_username(username)
        return HttpResponseRedirect(reverse("defender_blocks_view"))

admin.site.register(AccessAttempt, AccessAttemptAdmin)
