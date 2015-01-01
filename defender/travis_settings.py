
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
    'defender.middleware.ViewDecoratorMiddleware',
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

DEFENDER_LOGIN_FAILURE_LIMIT = 10
DEFENDER_COOLOFF_TIME = 2
DEFENDER_REDIS_URL = "redis://localhost:6379/1"
# don't use mock redis in unit tests, we will use real redis on travis.
DEFENDER_MOCK_REDIS = False
