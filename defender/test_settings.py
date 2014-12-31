import django

if django.VERSION[:2] >= (1, 3):
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    }
else:
    DATABASE_ENGINE = 'sqlite3'

SITE_ID = 1

REDIS_HOST = 'localhost'
REDIS_PORT = '1234'
REDIS_PASSWORD = 'mypassword'
REDIS_DB = 1

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'defender.middleware.FailedLoginMiddleware'
)

ROOT_URLCONF = 'defender.test_urls'

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.admin',
    'defender',
]

SECRET_KEY = 'too-secret-for-test'

LOGIN_REDIRECT_URL = '/admin'

AXES_LOGIN_FAILURE_LIMIT = 10
from datetime import timedelta
AXES_COOLOFF_TIME = timedelta(seconds=2)
