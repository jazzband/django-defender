import os

import django
from celery import Celery


DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:",}}

CACHES = {
    "default": {"BACKEND": "redis_cache.RedisCache", "LOCATION": "localhost:6379",}
}

SITE_ID = 1

MIDDLEWARE = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "defender.middleware.FailedLoginMiddleware",
)

ROOT_URLCONF = "defender.test_urls"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.admin",
    "defender",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
            ],
        },
    },
]

SECRET_KEY = os.environ.get("SECRET_KEY", "too-secret-for-test")

LOGIN_REDIRECT_URL = "/admin"

DEFENDER_LOGIN_FAILURE_LIMIT = 10
DEFENDER_COOLOFF_TIME = 2
DEFENDER_REDIS_URL = "redis://localhost:6379/1"
# don't use mock redis in unit tests, we will use real redis on CI.
DEFENDER_MOCK_REDIS = False

# Celery settings:
CELERY_ALWAYS_EAGER = True
BROKER_BACKEND = "memory"
BROKER_URL = "memory://"

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "defender.ci_settings")

app = Celery("defender")

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object("django.conf:settings")
app.autodiscover_tasks(lambda: INSTALLED_APPS)
