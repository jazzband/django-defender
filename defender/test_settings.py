import os

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}


SITE_ID = 1

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'defender.middleware.FailedLoginMiddleware',
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

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
    },
]

SECRET_KEY = os.environ.get('SECRET_KEY', 'too-secret-for-test')

LOGIN_REDIRECT_URL = '/admin'

DEFENDER_LOGIN_FAILURE_LIMIT = 10
DEFENDER_COOLOFF_TIME = 2
DEFENDER_REDIS_URL = None
# use mock redis in unit tests locally.
DEFENDER_MOCK_REDIS = True

# celery settings
CELERY_ALWAYS_EAGER = True
BROKER_BACKEND = 'memory'
BROKER_URL = 'memory://'

import os

from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'defender.test_settings')

app = Celery('defender')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')
app.autodiscover_tasks(lambda: INSTALLED_APPS)
