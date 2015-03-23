from . import utils
from . import config
from django.shortcuts import render_to_response
from django.template import RequestContext

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

        if func.__name__ == 'decorated_login':
            # if we're dealing with this function itself, don't bother checking
            # for invalid login attempts.  I suppose there's a bunch of
            # recursion going on here that used to cause one failed login
            # attempt to generate 10+ failed access attempt records (with 3
            # failed attempts each supposedly)
            return response

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

            login_attempt_status = utils.check_request(request, login_unsuccessful)

            if login_attempt_status in [config.LoginAttemptStatus.LOGIN_SUCCEED, config.LoginAttemptStatus.LOGIN_FAILED_PASS_USER]:
                return response

            elif login_attempt_status == config.LoginAttemptStatus.LOGIN_FAILED_LOCK_USER:
                return utils.lockout_response(request)

            elif login_attempt_status == config.LoginAttemptStatus.LOGIN_FAILED_SHOW_WARNING:
                return render_to_response('auth/login.html', {"error_list": ["Invalid email and/or password. "
                                                                             "WARNING: Your account will lock after 2 more unsuccessful login attempts."]},
                                                                             context_instance=RequestContext(request))

        return response

    return decorated_login
