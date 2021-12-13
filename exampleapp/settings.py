import os
from celery import Celery

PROJECT_DIR = lambda base: os.path.abspath(
    os.path.join(os.path.dirname(__file__), base).replace("\\", "/")
)


MEDIA_ROOT = PROJECT_DIR(os.path.join("media"))
MEDIA_URL = "/media/"
STATIC_ROOT = PROJECT_DIR(os.path.join("static"))
STATIC_URL = "/static/"

STATICFILES_DIRS = (PROJECT_DIR(os.path.join("media", "static")),)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": PROJECT_DIR("defender.sb"),
    }
}


SITE_ID = 1

MIDDLEWARE = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "defender.middleware.FailedLoginMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware"
)

ROOT_URLCONF = "exampleapp.urls"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.admin",
    "django.contrib.staticfiles",
    "defender",
]

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
)

SECRET_KEY = os.environ.get("SECRET_KEY", "too-secret-for-test")

LOGIN_REDIRECT_URL = "/admin"

DEFENDER_LOGIN_FAILURE_LIMIT = 1
DEFENDER_COOLOFF_TIME = 60
DEFENDER_REDIS_URL = "redis://localhost:6379/1"
# don't use mock redis in unit tests, we will use real redis on CI.
DEFENDER_MOCK_REDIS = False
# Let's use custom function and strip username string from request.
DEFENDER_GET_USERNAME_FROM_REQUEST_PATH = (
    "exampleapp.utils.strip_username_from_request"
)

# Celery settings:
CELERY_ALWAYS_EAGER = True
BROKER_BACKEND = "memory"
BROKER_URL = "memory://"

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "exampleapp.settings")

app = Celery("defender")

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object("django.conf:settings")
app.autodiscover_tasks(lambda: INSTALLED_APPS)

DEBUG = True

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]