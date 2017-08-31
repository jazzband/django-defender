from django.conf import settings
from django.utils.translation import ugettext_lazy

has_constance_app = True
try:
    from constance import config as constance_config
except ImportError:
    has_constance_app = False


def get_setting(variable, default=None, datetime_value=False):
    """ get the 'variable' from settings if not there use the
    provided default """
    if has_constance_app:
        setting = getattr(constance_config, variable, None)
        if setting is not None:
            return setting.seconds if datetime_value else setting

    return getattr(settings, variable, default)


# Evaluated settings =========================================================

def get_cooloff_time(pretty_print=False):
    """Method to get ``COOLOFF_TIME`` setting.

    As it can be specified in `constance` app - it's should always be
    retrieved by function call.

    """
    try:
        seconds = int(get_setting('DEFENDER_COOLOFF_TIME', 300, True))
    except ValueError:
        raise Exception('DEFENDER_COOLOFF_TIME needs to be an integer')

    # Return cooloff time as pretty string, like "1 minute 23 seconds"
    if pretty_print:
        result = []
        minutes = seconds // 60
        seconds = seconds % 60
        if minutes > 0:
            result.append(
                '{} minute{}'.format(minutes, '' if minutes == 1 else 's')
            )
        if seconds > 0:
            result.append(
                '{} second{}'.format(seconds, '' if seconds == 1 else 's')
            )
        return ' '.join(result)

    return seconds


def get_failure_limit():
    """Method to get ``FAILURE_LIMIT`` setting.

    As it can be specified in `constance` app - it's should always be
    retrieved by function call.

    """
    # see if the user has overridden the failure limit
    return get_setting('DEFENDER_LOGIN_FAILURE_LIMIT', 3)


# Constant settings ==========================================================

# redis server host
DEFENDER_REDIS_URL = get_setting('DEFENDER_REDIS_URL')

# reuse declared cache from django settings
DEFENDER_REDIS_NAME = get_setting('DEFENDER_REDIS_NAME')

MOCK_REDIS = get_setting('DEFENDER_MOCK_REDIS', False)

# If this is True, the lockout checks to evaluate if the IP failure limit and
# the username failure limit has been reached before issuing the lockout.
LOCKOUT_BY_IP_USERNAME = get_setting(
    'DEFENDER_LOCK_OUT_BY_IP_AND_USERNAME', False)

# if this is True, The users IP address will not get locked when
# there are too many login attempts.
DISABLE_IP_LOCKOUT = get_setting('DEFENDER_DISABLE_IP_LOCKOUT', False)

# If this is True, usernames will not get locked when
# there are too many login attempts.
DISABLE_USERNAME_LOCKOUT = get_setting(
    'DEFENDER_DISABLE_USERNAME_LOCKOUT', False)

# use a specific username field to retrieve from login POST data
USERNAME_FORM_FIELD = get_setting('DEFENDER_USERNAME_FORM_FIELD', 'username')

# see if the django app is sitting behind a reverse proxy
BEHIND_REVERSE_PROXY = get_setting('DEFENDER_BEHIND_REVERSE_PROXY', False)

# the prefix for these keys in your cache.
CACHE_PREFIX = get_setting('DEFENDER_CACHE_PREFIX', 'defender')

# if the django app is behind a reverse proxy, look for the
# ip address using this HTTP header value
REVERSE_PROXY_HEADER = get_setting('DEFENDER_REVERSE_PROXY_HEADER',
                                   'HTTP_X_FORWARDED_FOR')

LOCKOUT_TEMPLATE = get_setting('DEFENDER_LOCKOUT_TEMPLATE')

ERROR_MESSAGE = ugettext_lazy("Please enter a correct username and password. "
                              "Note that both fields are case-sensitive.")

LOCKOUT_URL = get_setting('DEFENDER_LOCKOUT_URL')

USE_CELERY = get_setting('DEFENDER_USE_CELERY', False)

STORE_ACCESS_ATTEMPTS = get_setting('DEFENDER_STORE_ACCESS_ATTEMPTS', True)

# Used by the management command to decide how long to keep access attempt
# recods. Number is # of hours.
try:
    ACCESS_ATTEMPT_EXPIRATION = int(get_setting(
        'DEFENDER_ACCESS_ATTEMPT_EXPIRATION', 24))
except ValueError:  # pragma: no cover
    raise Exception(
        'DEFENDER_ACCESS_ATTEMPT_EXPIRATION'
        ' needs to be an integer')  # pragma: no cover
