from . import utils


def watch_login(func):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    def decorated_login(request, *args, **kwargs):
        # if the request is currently under lockout, do not proceed to the
        # login function, go directly to lockout url, do not pass go, do not
        # collect messages about this login attempt
        if utils.is_already_locked(request):
            return utils.lockout_response(request)

        # call the login function
        response = func(request, *args, **kwargs)

        if request.method == 'POST':
            # see if the login was successful
            login_unsuccessful = (
                response and
                not response.has_header('location') and
                response.status_code != 302
            )

            # ideally make this background task, but to keep simple, keeping
            # it inline for now.
            utils.add_login_attempt_to_db(request, not login_unsuccessful)

            if utils.check_request(request, login_unsuccessful):
                return response

            return utils.lockout_response(request)

        return response

    return decorated_login
