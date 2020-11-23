from django.contrib.auth.views import LoginView
from django.utils.decorators import method_decorator

from .decorators import watch_login


class FailedLoginMiddleware:
    """ Failed login middleware """

    patched = False

    def __init__(self, get_response):
        self.get_response = get_response

        # Watch the auth login.
        # Monkey-patch only once - otherwise we would be recording
        # failed attempts multiple times!
        if not FailedLoginMiddleware.patched:
            our_decorator = watch_login()
            watch_login_method = method_decorator(our_decorator)
            LoginView.dispatch = watch_login_method(LoginView.dispatch)

            FailedLoginMiddleware.patched = True

    def __call__(self, request):
        response = self.get_response(request)
        return response