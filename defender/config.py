from django.conf import settings
from django.utils.translation import gettext_lazy


def get_setting(variable, default=None):
    """ get the 'variable' from settings if not there use the
    provided default """
    return getattr(settings, variable, default)


# redis server host
DEFENDER_REDIS_URL = get_setting("DEFENDER_REDIS_URL")

# redis password quote for special character
DEFENDER_REDIS_PASSWORD_QUOTE = get_setting("DEFENDER_REDIS_PASSWORD_QUOTE", False)

# reuse declared cache from django settings
DEFENDER_REDIS_NAME = get_setting("DEFENDER_REDIS_NAME")

MOCK_REDIS = get_setting("DEFENDER_MOCK_REDIS", False)

# see if the user has overridden the failure limit
FAILURE_LIMIT = get_setting("DEFENDER_LOGIN_FAILURE_LIMIT", 3)
USERNAME_FAILURE_LIMIT = get_setting(
    "DEFENDER_LOGIN_FAILURE_LIMIT_USERNAME", FAILURE_LIMIT
)
IP_FAILURE_LIMIT = get_setting("DEFENDER_LOGIN_FAILURE_LIMIT_IP", FAILURE_LIMIT)

# If this is True, the lockout checks to evaluate if the IP failure limit and
# the username failure limit has been reached before issuing the lockout.
LOCKOUT_BY_IP_USERNAME = get_setting("DEFENDER_LOCK_OUT_BY_IP_AND_USERNAME", False)

# if this is True, The users IP address will not get locked when
# there are too many login attempts.
DISABLE_IP_LOCKOUT = get_setting("DEFENDER_DISABLE_IP_LOCKOUT", False)

# If this is True, usernames will not get locked when
# there are too many login attempts.
DISABLE_USERNAME_LOCKOUT = get_setting("DEFENDER_DISABLE_USERNAME_LOCKOUT", False)

# use a specific username field to retrieve from login POST data
USERNAME_FORM_FIELD = get_setting("DEFENDER_USERNAME_FORM_FIELD", "username")

# see if the django app is sitting behind a reverse proxy
BEHIND_REVERSE_PROXY = get_setting("DEFENDER_BEHIND_REVERSE_PROXY", False)

# the prefix for these keys in your cache.
CACHE_PREFIX = get_setting("DEFENDER_CACHE_PREFIX", "defender")

# if the django app is behind a reverse proxy, look for the
# ip address using this HTTP header value
REVERSE_PROXY_HEADER = get_setting(
    "DEFENDER_REVERSE_PROXY_HEADER", "HTTP_X_FORWARDED_FOR"
)

try:
    # how long to wait before the bad login attempt/lockout gets forgotten, in seconds.
    COOLOFF_TIME = int(get_setting("DEFENDER_COOLOFF_TIME", 300))  # seconds
    try:
        # how long to wait before the bad login attempt gets forgotten, in seconds.
        ATTEMPT_COOLOFF_TIME = int(get_setting("DEFENDER_ATTEMPT_COOLOFF_TIME", COOLOFF_TIME))  # measured in seconds
    except ValueError:  # pragma: no cover
        raise Exception("DEFENDER_ATTEMPT_COOLOFF_TIME needs to be an integer")  # pragma: no cover

    try:
        # how long to wait before a lockout gets forgotten, in seconds.
        LOCKOUT_COOLOFF_TIMES = [int(get_setting("DEFENDER_LOCKOUT_COOLOFF_TIME", COOLOFF_TIME))]  # measured in seconds
    except TypeError:  # pragma: no cover
        try:  # pragma: no cover
            cooloff_times = get_setting("DEFENDER_LOCKOUT_COOLOFF_TIME", [COOLOFF_TIME])  # measured in seconds
            for index, cooloff_time in enumerate(cooloff_times):  # pragma: no cover
                cooloff_times[index] = int(cooloff_time)  # pragma: no cover

            if not len(cooloff_times):  # pragma: no cover
                raise TypeError()  # pragma: no cover

            LOCKOUT_COOLOFF_TIMES = cooloff_times
        except (TypeError, ValueError):  # pragma: no cover
            raise Exception("DEFENDER_LOCKOUT_COOLOFF_TIME needs to be an integer or list of integers having at least one element")  # pragma: no cover
    except ValueError:  # pragma: no cover
        raise Exception("DEFENDER_LOCKOUT_COOLOFF_TIME needs to be an integer or list of integers having at least one element")  # pragma: no cover
except ValueError:  # pragma: no cover
    raise Exception("DEFENDER_COOLOFF_TIME needs to be an integer")  # pragma: no cover

LOCKOUT_TEMPLATE = get_setting("DEFENDER_LOCKOUT_TEMPLATE")

ERROR_MESSAGE = gettext_lazy(
    "Please enter a correct username and password. "
    "Note that both fields are case-sensitive."
)

LOCKOUT_URL = get_setting("DEFENDER_LOCKOUT_URL")

USE_CELERY = get_setting("DEFENDER_USE_CELERY", False)

STORE_ACCESS_ATTEMPTS = get_setting("DEFENDER_STORE_ACCESS_ATTEMPTS", True)

# Used by the management command to decide how long to keep access attempt
# recods. Number is # of hours.
try:
    ACCESS_ATTEMPT_EXPIRATION = int(
        get_setting("DEFENDER_ACCESS_ATTEMPT_EXPIRATION", 24)
    )
except ValueError:  # pragma: no cover
    raise Exception(
        "DEFENDER_ACCESS_ATTEMPT_EXPIRATION" " needs to be an integer"
    )  # pragma: no cover


GET_USERNAME_FROM_REQUEST_PATH = get_setting(
    "DEFENDER_GET_USERNAME_FROM_REQUEST_PATH", "defender.utils.username_from_request"
)
