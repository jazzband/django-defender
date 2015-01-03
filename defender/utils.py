import logging
import socket

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext

from .models import AccessAttempt
from .connection import get_redis_connection
from . import config

redis_server = get_redis_connection()

log = logging.getLogger(__name__)


def is_valid_ip(ip_address):
    """ Check Validity of an IP address """
    valid = True
    try:
        socket.inet_aton(ip_address.strip())
    except (socket.error, AttributeError):
        valid = False
    return valid


def get_ip_address_from_request(request):
    """ Makes the best attempt to get the client's real IP or return
        the loopback """
    PRIVATE_IPS_PREFIX = ('10.', '172.', '192.', '127.')
    ip_address = ''
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if x_forwarded_for and ',' not in x_forwarded_for:
        if not x_forwarded_for.startswith(PRIVATE_IPS_PREFIX) and is_valid_ip(
                x_forwarded_for):
            ip_address = x_forwarded_for.strip()
    else:
        ips = [ip.strip() for ip in x_forwarded_for.split(',')]
        for ip in ips:
            if ip.startswith(PRIVATE_IPS_PREFIX):
                continue
            elif not is_valid_ip(ip):
                continue
            else:
                ip_address = ip
                break
    if not ip_address:
        x_real_ip = request.META.get('HTTP_X_REAL_IP', '')
        if x_real_ip:
            if not x_real_ip.startswith(PRIVATE_IPS_PREFIX) and is_valid_ip(
                    x_real_ip):
                ip_address = x_real_ip.strip()
    if not ip_address:
        remote_addr = request.META.get('REMOTE_ADDR', '')
        if remote_addr:
            if not remote_addr.startswith(PRIVATE_IPS_PREFIX) and is_valid_ip(
                    remote_addr):
                ip_address = remote_addr.strip()
            if remote_addr.startswith(PRIVATE_IPS_PREFIX) and is_valid_ip(
                    remote_addr):
                ip_address = remote_addr.strip()
    if not ip_address:
        ip_address = '127.0.0.1'
    return ip_address


def get_ip(request):
    """ get the ip address from the request """
    if not config.BEHIND_REVERSE_PROXY:
        ip = get_ip_address_from_request(request)
    else:
        ip = request.META.get(config.REVERSE_PROXY_HEADER, '')
        ip = ip.split(",", 1)[0].strip()
        if ip == '':
            ip = request.META.get('REMOTE_ADDR', '')
    return ip


def get_ip_attempt_cache_key(ip):
    """ get the cache key by ip """
    return "{0}:failed:ip:{1}".format(config.CACHE_PREFIX, ip)


def get_username_attempt_cache_key(username):
    """ get the cache key by username """
    return "{0}:failed:username:{1}".format(config.CACHE_PREFIX, username)


def get_ip_blocked_cache_key(ip):
    """ get the cache key by ip """
    return "{0}:blocked:ip:{1}".format(config.CACHE_PREFIX, ip)


def get_username_blocked_cache_key(username):
    """ get the cache key by username """
    return "{0}:blocked:username:{1}".format(config.CACHE_PREFIX, username)


def increment_key(key):
    """ given a key increment the value """
    pipe = redis_server.pipeline()
    pipe.incr(key, 1)
    if config.COOLOFF_TIME:
        pipe.expire(key, config.COOLOFF_TIME)
    new_value = pipe.execute()[0]
    return new_value


def get_user_attempts(request):
    """ Returns number of access attempts for this ip, username
    """
    ip = get_ip(request)

    username = request.POST.get(config.USERNAME_FORM_FIELD, None)

    # get by IP
    ip_count = redis_server.get(get_ip_attempt_cache_key(ip))
    if not ip_count:
        ip_count = 0
    ip_count = int(ip_count)

    # get by username
    username_count = redis_server.get(get_username_attempt_cache_key(username))
    if not username_count:
        username_count = 0
    username_count = int(username_count)

    # return the larger of the two.
    return max(ip_count, username_count)


def block_ip(ip):
    """ given the ip, block it """
    key = get_ip_blocked_cache_key(ip)
    if config.COOLOFF_TIME:
        redis_server.set(key, 'blocked', config.COOLOFF_TIME)
    else:
        redis_server.set(key, 'blocked')


def block_username(username):
    """ given the username block it. """
    key = get_username_blocked_cache_key(username)
    if config.COOLOFF_TIME:
        redis_server.set(key, 'blocked', config.COOLOFF_TIME)
    else:
        redis_server.set(key, 'blocked')


def record_failed_attempt(ip, username):
    """ record the failed login attempt, if over limit return False,
    if not over limit return True """
    # increment the failed count, and get current number
    ip_count = increment_key(get_ip_attempt_cache_key(ip))
    user_count = increment_key(get_username_attempt_cache_key(username))

    # if either are over the limit, add to block
    if ip_count > config.FAILURE_LIMIT or user_count > config.FAILURE_LIMIT:
        block_ip(ip)
        block_username(username)
        return False
    return True


def reset_failed_attempts(ip=None, username=None):
    """ reset the failed attempts for these ip's and usernames
    """
    pipe = redis_server.pipeline()
    if ip:
        pipe.delete(get_ip_attempt_cache_key(ip))
        pipe.delete(get_ip_blocked_cache_key(ip))
    if username:
        pipe.delete(get_username_attempt_cache_key(username))
        pipe.delete(get_username_blocked_cache_key(username))
    pipe.execute()


def lockout_response(request):
    """ if we are locked out, here is the response """
    if config.LOCKOUT_TEMPLATE:
        context = {
            'cooloff_time': config.COOLOFF_TIME,
            'failure_limit': config.FAILURE_LIMIT,
        }
        return render_to_response(config.LOCKOUT_TEMPLATE, context,
                                  context_instance=RequestContext(request))

    if config.LOCKOUT_URL:
        return HttpResponseRedirect(config.LOCKOUT_URL)

    if config.COOLOFF_TIME:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Please try again later.")
    else:
        return HttpResponse("Account locked: too many login attempts.  "
                            "Contact an admin to unlock your account.")


def is_already_locked(request):
    """ Is this IP/username already locked? """
    ip_address = get_ip(request)
    username = request.POST.get(config.USERNAME_FORM_FIELD, None)

    # ip blocked?
    ip_blocked = redis_server.get(get_ip_blocked_cache_key(ip_address))

    if not ip_blocked:
        ip_blocked = False
    else:
        # short circuit no need to check username if ip is already blocked.
        return True

    # username blocked?
    user_blocked = redis_server.get(get_username_blocked_cache_key(username))
    if not user_blocked:
        user_blocked = False

    return ip_blocked or user_blocked


def check_request(request, login_unsuccessful):
    """ check the request, and process results"""
    ip_address = get_ip(request)
    username = request.POST.get(config.USERNAME_FORM_FIELD, None)

    if not login_unsuccessful:
        # user logged in -- forget the failed attempts
        reset_failed_attempts(ip=ip_address, username=username)
        return True
    else:
        # add a failed attempt for this user
        return record_failed_attempt(ip_address, username)


def add_login_attempt(request, login_valid):
    """ Create a record for the login attempt """
    AccessAttempt.objects.create(
        user_agent=request.META.get('HTTP_USER_AGENT',
                                    '<unknown>')[:255],
        ip_address=get_ip(request),
        username=request.POST.get(config.USERNAME_FORM_FIELD, None),
        http_accept=request.META.get('HTTP_ACCEPT', '<unknown>'),
        path_info=request.META.get('PATH_INFO', '<unknown>'),
        login_valid=login_valid,
    )
