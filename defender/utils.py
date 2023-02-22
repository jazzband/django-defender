from ipaddress import ip_address
import logging
import re
import sys

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError
from django.utils.module_loading import import_string

from .connection import get_redis_connection
from . import config
from .data import get_approx_account_lockouts_from_login_attempts, store_login_attempt
from .signals import (
    send_username_block_signal,
    send_ip_block_signal,
    send_username_unblock_signal,
    send_ip_unblock_signal,
)

REDIS_SERVER = get_redis_connection()

LOG = logging.getLogger(__name__)


def is_valid_ip(ip_address):
    """ Check Validity of an IP address """
    if not ip_address:
        return False
    ip_address = ip_address.strip()
    try:
        validate_ipv46_address(ip_address)
        return True
    except ValidationError:
        return False


def get_ip_address_from_request(request):
    """ Makes the best attempt to get the client's real IP or return
        the loopback """
    remote_addr = request.META.get("REMOTE_ADDR", "")
    if remote_addr and is_valid_ip(remote_addr):
        return remote_addr.strip()
    return "127.0.0.1"


ipv4_with_port = re.compile(r"^(\d+\.\d+\.\d+\.\d+):\d+")
ipv6_with_port = re.compile(r"^\[([^\]]+)\]:\d+")


def strip_port_number(ip_address_string):
    """ strips port number from IPv4 or IPv6 address """
    ip_address = None

    if ipv4_with_port.match(ip_address_string):
        match = ipv4_with_port.match(ip_address_string)
        ip_address = match[1]
    elif ipv6_with_port.match(ip_address_string):
        match = ipv6_with_port.match(ip_address_string)
        ip_address = match[1]

    """
    If it's not a valid IP address, we prefer to return
    the string as-is instead of returning a potentially 
    corrupted string:
    """
    if is_valid_ip(ip_address):
        return ip_address

    return ip_address_string


def get_ip(request):
    """ get the ip address from the request """
    if config.BEHIND_REVERSE_PROXY:
        ip_address = request.META.get(config.REVERSE_PROXY_HEADER, "")
        ip_address = ip_address.split(",", 1)[0].strip()

        if ip_address == "":
            ip_address = get_ip_address_from_request(request)
        else:
            """
            Some reverse proxies will include a port number with the
            IP address; as this port may change from request to request,
            and thus make it appear to be different IP addresses, we'll
            want to remove the port number, if present:
            """
            ip_address = strip_port_number(ip_address)
    else:
        ip_address = get_ip_address_from_request(request)

    return ip_address


def lower_username(username):
    """
    Single entry point to force the username to lowercase, all the functions
    that need to deal with username should call this.
    """
    if username:
        return username.lower()
    return None


def get_ip_attempt_cache_key(ip_address):
    """ get the cache key by ip """
    return "{0}:failed:ip:{1}".format(config.CACHE_PREFIX, ip_address)


def get_username_attempt_cache_key(username):
    """ get the cache key by username """
    return "{0}:failed:username:{1}".format(
        config.CACHE_PREFIX, lower_username(username)
    )


def get_ip_blocked_cache_key(ip_address):
    """ get the cache key by ip """
    return "{0}:blocked:ip:{1}".format(config.CACHE_PREFIX, ip_address)


def get_username_blocked_cache_key(username):
    """ get the cache key by username """
    return "{0}:blocked:username:{1}".format(
        config.CACHE_PREFIX, lower_username(username)
    )


def remove_prefix(string, prefix):
    if string.startswith(prefix):
        return string[len(prefix):]
    return string



def strip_keys(key_list):
    """ Given a list of keys, remove the prefix and remove just
    the data we care about.

    for example:

        [
            'defender:blocked:ip:192.168.24.24',
            'defender:blocked:ip:::ffff:192.168.24.24',
            'defender:blocked:username:joffrey'
        ]

    would result in:

        [
            '192.168.24.24',
            '::ffff:192.168.24.24',
            'joffrey'
        ]
    """
    return [
        # key.removeprefix(f"{config.CACHE_PREFIX}:blocked:").partition(":")[2]
        remove_prefix(key, f"{config.CACHE_PREFIX}:blocked:").partition(":")[2]
        for key in key_list
    ]


def get_blocked_ips():
    """ get a list of blocked ips from redis """
    if config.DISABLE_IP_LOCKOUT:
        # There are no blocked IP's since we disabled them.
        return []
    key = get_ip_blocked_cache_key("*")
    key_list = [redis_key.decode("utf-8") for redis_key in REDIS_SERVER.keys(key)]
    return strip_keys(key_list)


def get_blocked_usernames():
    """ get a list of blocked usernames from redis """
    if config.DISABLE_USERNAME_LOCKOUT:
        # There are no blocked usernames since we disabled them.
        return []
    key = get_username_blocked_cache_key("*")
    key_list = [redis_key.decode("utf-8") for redis_key in REDIS_SERVER.keys(key)]
    return strip_keys(key_list)


def increment_key(key):
    """ given a key increment the value """
    pipe = REDIS_SERVER.pipeline()
    pipe.incr(key, 1)
    if config.ATTEMPT_COOLOFF_TIME:
        pipe.expire(key, config.ATTEMPT_COOLOFF_TIME)
    new_value = pipe.execute()[0]
    return new_value


def username_from_request(request):
    """ unloads username from default POST request """
    if config.USERNAME_FORM_FIELD in request.POST:
        return request.POST[config.USERNAME_FORM_FIELD][:255]
    return None


get_username_from_request = import_string(config.GET_USERNAME_FROM_REQUEST_PATH)


def get_user_attempts(request, get_username=get_username_from_request, username=None):
    """ Returns number of access attempts for this ip, username
    """
    ip_address = get_ip(request)

    username = lower_username(username or get_username(request))

    # get by IP
    ip_count = REDIS_SERVER.get(get_ip_attempt_cache_key(ip_address))
    if not ip_count:
        ip_count = 0
    ip_count = int(ip_count)

    # get by username
    username_count = REDIS_SERVER.get(get_username_attempt_cache_key(username))
    if not username_count:
        username_count = 0
    username_count = int(username_count)

    # return the larger of the two.
    return max(ip_count, username_count)

def get_lockout_cooloff_time(ip_address=None, username=None):
    if not config.LOCKOUT_COOLOFF_TIMES:
        return 0
    index = max(0, min(
        len(config.LOCKOUT_COOLOFF_TIMES) - 1,
        get_approx_account_lockouts_from_login_attempts(ip_address, username) - 1
    ))
    return config.LOCKOUT_COOLOFF_TIMES[index]


def block_ip(ip_address):
    """ given the ip, block it """
    if not ip_address:
        # no reason to continue when there is no ip
        return
    if config.DISABLE_IP_LOCKOUT:
        # no need to block, we disabled it.
        return
    already_blocked = is_source_ip_already_locked(ip_address)
    key = get_ip_blocked_cache_key(ip_address)
    cooloff_time = get_lockout_cooloff_time(ip_address=ip_address)
    if cooloff_time:
        REDIS_SERVER.set(key, "blocked", cooloff_time)
    else:
        REDIS_SERVER.set(key, "blocked")
    if not already_blocked:
        send_ip_block_signal(ip_address)


def block_username(username):
    """ given the username block it. """
    if not username:
        # no reason to continue when there is no username
        return
    if config.DISABLE_USERNAME_LOCKOUT:
        # no need to block, we disabled it.
        return
    already_blocked = is_user_already_locked(username)
    key = get_username_blocked_cache_key(username)
    cooloff_time = get_lockout_cooloff_time(username=username)
    if cooloff_time:
        REDIS_SERVER.set(key, "blocked", cooloff_time)
    else:
        REDIS_SERVER.set(key, "blocked")
    if not already_blocked:
        send_username_block_signal(username)


def record_failed_attempt(ip_address, username):
    """ record the failed login attempt, if over limit return False,
    if not over limit return True """
    # increment the failed count, and get current number
    ip_block = False
    if not config.DISABLE_IP_LOCKOUT:
        # we only want to increment the IP if this is disabled.
        ip_count = increment_key(get_ip_attempt_cache_key(ip_address))
        # if over the limit, add to block
        if ip_count > config.IP_FAILURE_LIMIT:
            block_ip(ip_address)
            ip_block = True

    user_block = False
    if username and not config.DISABLE_USERNAME_LOCKOUT:
        user_count = increment_key(get_username_attempt_cache_key(username))
        # if over the limit, add to block
        if user_count > config.USERNAME_FAILURE_LIMIT:
            block_username(username)
            user_block = True

    # if we have this turned on, then there is no reason to look at ip_block
    # we will just look at user_block, and short circut the result since
    # we don't need to continue.
    if config.DISABLE_IP_LOCKOUT:
        # if user_block is True, it means it was blocked
        # we need to return False
        return not user_block

    if config.DISABLE_USERNAME_LOCKOUT:
        # The same as DISABLE_IP_LOCKOUT
        return not ip_block

    # we want to make sure both the IP and user is blocked before we
    # return False
    # this is mostly used when a lot of your users are using proxies,
    # and you don't want one user to block everyone on that one IP.
    if config.LOCKOUT_BY_IP_USERNAME:
        # both ip_block and user_block need to be True in order
        # to return a False.
        return not (ip_block and user_block)

    # if any blocks return False, no blocks. return True
    return not (ip_block or user_block)


def unblock_ip(ip_address, pipe=None):
    """ unblock the given IP """
    do_commit = False
    if not pipe:
        pipe = REDIS_SERVER.pipeline()
        do_commit = True
    if ip_address:
        pipe.delete(get_ip_attempt_cache_key(ip_address))
        pipe.delete(get_ip_blocked_cache_key(ip_address))
        if do_commit:
            pipe.execute()
    send_ip_unblock_signal(ip_address)


def unblock_username(username, pipe=None):
    """ unblock the given Username """
    do_commit = False
    if not pipe:
        pipe = REDIS_SERVER.pipeline()
        do_commit = True
    if username:
        pipe.delete(get_username_attempt_cache_key(username))
        pipe.delete(get_username_blocked_cache_key(username))
        if do_commit:
            pipe.execute()
    send_username_unblock_signal(username)


def reset_failed_attempts(ip_address=None, username=None):
    """ reset the failed attempts for these ip's and usernames
    """
    pipe = REDIS_SERVER.pipeline()

    # Because IP is shared, a reset should never clear an IP block
    # when using IP/username as block
    if not config.LOCKOUT_BY_IP_USERNAME:
        unblock_ip(ip_address, pipe=pipe)
    unblock_username(username, pipe=pipe)

    pipe.execute()


def lockout_response(request):
    """ if we are locked out, here is the response """
    ip_address = get_ip(request)
    username = get_username_from_request(request)
    if config.LOCKOUT_TEMPLATE:
        cooloff_time = get_lockout_cooloff_time(ip_address=ip_address, username=username)
        context = {
            "cooloff_time_seconds": cooloff_time,
            "cooloff_time_minutes": cooloff_time / 60,
            "failure_limit": config.FAILURE_LIMIT,
        }
        return render(request, config.LOCKOUT_TEMPLATE, context)

    if config.LOCKOUT_URL:
        return HttpResponseRedirect(config.LOCKOUT_URL)

    if get_lockout_cooloff_time(ip_address=ip_address, username=username):
        return HttpResponse(
            "Account locked: too many login attempts.  " "Please try again later."
        )
    else:
        return HttpResponse(
            "Account locked: too many login attempts.  "
            "Contact an admin to unlock your account."
        )


def is_user_already_locked(username):
    """Is this username already locked?"""
    if username is None:
        return False
    if config.DISABLE_USERNAME_LOCKOUT:
        return False
    return REDIS_SERVER.get(get_username_blocked_cache_key(username))


def is_source_ip_already_locked(ip_address):
    """Is this IP already locked?"""
    if ip_address is None:
        return False
    if config.DISABLE_IP_LOCKOUT:
        return False
    return REDIS_SERVER.get(get_ip_blocked_cache_key(ip_address))


def is_already_locked(request, get_username=get_username_from_request, username=None):
    """Parse the username & IP from the request, and see if it's
    already locked."""
    user_blocked = is_user_already_locked(username or get_username(request))
    ip_blocked = is_source_ip_already_locked(get_ip(request))

    if config.LOCKOUT_BY_IP_USERNAME:
        # if both this IP and this username are present the request is blocked
        return ip_blocked and user_blocked

    return ip_blocked or user_blocked


def check_request(
    request, login_unsuccessful, get_username=get_username_from_request, username=None
):
    """ check the request, and process results"""
    ip_address = get_ip(request)
    username = username or get_username(request)

    if not login_unsuccessful:
        # user logged in -- forget the failed attempts
        reset_failed_attempts(ip_address=ip_address, username=username)
        return True
    else:
        # add a failed attempt for this user
        return record_failed_attempt(ip_address, username)


def add_login_attempt_to_db(
    request, login_valid, get_username=get_username_from_request, username=None
):
    """ Create a record for the login attempt If using celery call celery
    task, if not, call the method normally """

    if not config.STORE_ACCESS_ATTEMPTS:
        # If we don't want to store in the database, then don't proceed.
        return

    username = username or get_username(request)

    user_agent = request.META.get("HTTP_USER_AGENT", "<unknown>")[:255]
    ip_address = get_ip(request)
    http_accept = request.META.get("HTTP_ACCEPT", "<unknown>")
    path_info = request.META.get("PATH_INFO", "<unknown>")

    if config.USE_CELERY:
        from .tasks import add_login_attempt_task

        add_login_attempt_task.delay(
            user_agent, ip_address, username, http_accept, path_info, login_valid
        )
    else:
        store_login_attempt(
            user_agent, ip_address, username, http_accept, path_info, login_valid
        )
