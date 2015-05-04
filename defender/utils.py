import logging

from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError

from .connection import get_redis_connection
from . import config
from .data import store_login_attempt

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
    remote_addr = request.META.get('REMOTE_ADDR', '')
    if remote_addr and is_valid_ip(remote_addr):
        return remote_addr.strip()
    return '127.0.0.1'


def get_ip(request):
    """ get the ip address from the request """
    if config.BEHIND_REVERSE_PROXY:
        ip_address = request.META.get(config.REVERSE_PROXY_HEADER, '')
        ip_address = ip_address.split(",", 1)[0].strip()
        if ip_address == '':
            ip_address = get_ip_address_from_request(request)
    else:
        ip_address = get_ip_address_from_request(request)
    return ip_address


def get_ip_attempt_cache_key(ip_address):
    """ get the cache key by ip """
    return "{0}:failed:ip:{1}".format(config.CACHE_PREFIX, ip_address)


def get_username_attempt_cache_key(username):
    """ get the cache key by username """
    return "{0}:failed:username:{1}".format(config.CACHE_PREFIX, username)


def get_ip_blocked_cache_key(ip_address):
    """ get the cache key by ip """
    return "{0}:blocked:ip:{1}".format(config.CACHE_PREFIX, ip_address)


def get_username_blocked_cache_key(username):
    """ get the cache key by username """
    return "{0}:blocked:username:{1}".format(config.CACHE_PREFIX, username)


def strip_keys(key_list):
    """ Given a list of keys, remove the prefix and remove just
    the data we care about.

    for example:

        ['defender:blocked:ip:ken', 'defender:blocked:ip:joffrey']

    would result in:

        ['ken', 'joffrey']

    """
    return [key.split(":")[-1] for key in key_list]


def get_blocked_ips():
    """ get a list of blocked ips from redis """
    key = get_ip_blocked_cache_key("*")
    key_list = REDIS_SERVER.keys(key)
    return strip_keys(key_list)


def get_blocked_usernames():
    """ get a list of blocked usernames from redis """
    key = get_username_blocked_cache_key("*")
    key_list = REDIS_SERVER.keys(key)
    return strip_keys(key_list)


def increment_key(key):
    """ given a key increment the value """
    pipe = REDIS_SERVER.pipeline()
    pipe.incr(key, 1)
    if config.COOLOFF_TIME:
        pipe.expire(key, config.COOLOFF_TIME)
    new_value = pipe.execute()[0]
    return new_value


def get_user_attempts(request):
    """ Returns number of access attempts for this ip, username
    """
    ip_address = get_ip(request)

    username = request.POST.get(config.USERNAME_FORM_FIELD, None)

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


def block_ip(ip_address):
    """ given the ip, block it """
    if not ip_address:
        # no reason to continue when there is no ip
        return
    key = get_ip_blocked_cache_key(ip_address)
    if config.COOLOFF_TIME:
        REDIS_SERVER.set(key, 'blocked', config.COOLOFF_TIME)
    else:
        REDIS_SERVER.set(key, 'blocked')


def block_username(username):
    """ given the username block it. """
    if not username:
        # no reason to continue when there is no username
        return
    key = get_username_blocked_cache_key(username)
    if config.COOLOFF_TIME:
        REDIS_SERVER.set(key, 'blocked', config.COOLOFF_TIME)
    else:
        REDIS_SERVER.set(key, 'blocked')


def record_failed_attempt(ip_address, username):
    """ record the failed login attempt, if over limit return False,
    if not over limit return True """
    # increment the failed count, and get current number
    ip_count = increment_key(get_ip_attempt_cache_key(ip_address))
    user_count = increment_key(get_username_attempt_cache_key(username))

    ip_block = False
    user_block = False
    # if either are over the limit, add to block
    if ip_count > config.FAILURE_LIMIT:
        block_ip(ip_address)
        ip_block = True
    if user_count > config.FAILURE_LIMIT:
        block_username(username)
        user_block = True

    if config.LOCKOUT_BY_IP_USERNAME:
        return not (ip_block and user_block)

    # if any blocks return False, no blocks return True
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


def reset_failed_attempts(ip_address=None, username=None):
    """ reset the failed attempts for these ip's and usernames
    """
    pipe = REDIS_SERVER.pipeline()

    unblock_ip(ip_address, pipe=pipe)
    unblock_username(username, pipe=pipe)

    pipe.execute()


def lockout_response(request):
    """ if we are locked out, here is the response """
    if config.LOCKOUT_TEMPLATE:
        context = {
            'cooloff_time_seconds': config.COOLOFF_TIME,
            'cooloff_time_minutes': config.COOLOFF_TIME / 60,
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
    ip_blocked = REDIS_SERVER.get(get_ip_blocked_cache_key(ip_address))

    # username blocked?
    user_blocked = REDIS_SERVER.get(get_username_blocked_cache_key(username))

    if config.LOCKOUT_BY_IP_USERNAME:
        LOG.info("Block by ip & username")
        if ip_blocked and user_blocked:
            # if both this IP and this username are present the request is
            # blocked
            return True

    else:
        if ip_blocked:
            # short circuit no need to check username if ip is already blocked.
            return True

        if user_blocked:
            return True

    # if the username nor ip is blocked, the request is not blocked
    return False


def check_request(request, login_unsuccessful):
    """ check the request, and process results"""
    ip_address = get_ip(request)
    username = request.POST.get(config.USERNAME_FORM_FIELD, None)

    if not login_unsuccessful:
        # user logged in -- forget the failed attempts
        reset_failed_attempts(ip_address=ip_address, username=username)
        return True
    else:
        # add a failed attempt for this user
        return record_failed_attempt(ip_address, username)


def add_login_attempt_to_db(request, login_valid):
    """ Create a record for the login attempt If using celery call celery
    task, if not, call the method normally """

    if not config.STORE_ACCESS_ATTEMPTS:
        # If we don't want to store in the database, then don't proceed.
        return

    user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
    ip_address = get_ip(request)
    username = request.POST.get(config.USERNAME_FORM_FIELD, None)
    http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')
    path_info = request.META.get('PATH_INFO', '<unknown>')

    if config.USE_CELERY:
        from .tasks import add_login_attempt_task
        add_login_attempt_task.delay(user_agent, ip_address, username,
                                     http_accept, path_info, login_valid)
    else:
        store_login_attempt(user_agent, ip_address, username,
                            http_accept, path_info, login_valid)
