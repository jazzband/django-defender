from django.conf import settings
from django.utils.translation import ugettext_lazy

class LoginAttemptStatus(object):

    values = ['LOGIN_SUCCEED','LOGIN_FAILED_SHOW_WARNING','LOGIN_FAILED_LOCK_USER', 'LOGIN_FAILED_PASS_USER']

    class __metaclass__(type):
        def __getattr__(self, name):
            return self.values.index(name)

def get_setting(variable, default=None):
    """ get the 'variable' from settings if not there use the
    provided default """
    return getattr(settings, variable, default)

# redis server host
DEFENDER_REDIS_URL = get_setting('DEFENDER_REDIS_URL')

MOCK_REDIS = get_setting('DEFENDER_MOCK_REDIS', False)

# see if the user has overridden the failure limit
FAILURE_LIMIT = get_setting('DEFENDER_LOGIN_FAILURE_LIMIT', 3)

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

try:
    # how long to wait before the bad login attempt gets forgotten. in seconds.
    COOLOFF_TIME = int(get_setting('DEFENDER_COOLOFF_TIME', 300))  # seconds
except ValueError:  # pragma: no cover
    raise Exception('COOLOFF_TIME needs to be an integer')  # pragma: no cover

LOCKOUT_TEMPLATE = get_setting('DEFENDER_LOCKOUT_TEMPLATE')

ERROR_MESSAGE = ugettext_lazy("Please enter a correct username and password. "
                              "Note that both fields are case-sensitive.")

# use a specific username field to retrieve from login POST data
USERNAME_FORM_FIELD = get_setting('DEFENDER_USERNAME_FORM_FIELD', 'username')

LOCKOUT_URL = get_setting('DEFENDER_LOCKOUT_URL')


USE_CELERY = get_setting('DEFENDER_USE_CELERY', False)
