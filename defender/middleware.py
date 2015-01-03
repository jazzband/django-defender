from django.contrib.auth import views as auth_views

from .decorators import watch_login
from .config import PROTECTED_LOGINS


class FailedLoginMiddleware(object):
    def __init__(self, *args, **kwargs):
        super(FailedLoginMiddleware, self).__init__(*args, **kwargs)

        # watch the auth login
        auth_views.login = watch_login(auth_views.login)


class ViewDecoratorMiddleware(object):
    """
    When the django_axes middleware is installed, by default it watches the
    django.auth.views.login.
    This middleware allows adding protection to other views without the need
    to change any urls or dectorate them manually.
    Add this middleware to your MIDDLEWARE settings after
    `defender.middleware.FailedLoginMiddleware` and before the django
    flatpages middleware.
    """

    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.path in PROTECTED_LOGINS:
            return watch_login(view_func)(request, *view_args, **view_kwargs)
        return None
