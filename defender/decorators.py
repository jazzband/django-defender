from . import utils

import functools


def watch_login(status_code=302, msg="", get_username=utils.get_username_from_request):
    """
    Used to decorate the django.contrib.admin.site.login method or
    any other function you want to protect by brute forcing.
    To make it work on normal functions just pass the status code that should
    indicate a failure and/or a string that will be checked within the
    response body.
    """

    def decorated_login(func):
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            # if the request is currently under lockout, do not proceed to the
            # login function, go directly to lockout url, do not pass go,
            # do not collect messages about this login attempt
            if utils.is_already_locked(request):
                return utils.lockout_response(request)

            # call the login function
            response = func(request, *args, **kwargs)

            if request.method == "POST":
                # see if the login was successful
                if status_code == 302:  # standard Django login view
                    login_unsuccessful = (
                        response
                        and not response.has_header("location")
                        and response.status_code != status_code
                    )
                else:
                    # If msg is passed as None then response object will not be accessed
                    # and response content will not be checked.
                    # This is especially useful when overriding non standard login
                    # views, like some custom Django REST login view.
                    # If msg is not passed at all then msg condition will always be
                    # evaluated to True so only first 2 will decide the result.
                    contains_msg = True  # defaults to True if msg is None

                    if msg is not None:
                        # Check if response's content contains provided msg
                        contains_msg = msg in response.content.decode("utf-8")

                    login_unsuccessful = (
                        response
                        and response.status_code == status_code
                        and contains_msg
                    )

                # ideally make this background task, but to keep simple,
                # keeping it inline for now.
                utils.add_login_attempt_to_db(
                    request, not login_unsuccessful, get_username
                )

                if utils.check_request(request, login_unsuccessful, get_username):
                    return response

                return utils.lockout_response(request)

            return response

        return wrapper

    return decorated_login
