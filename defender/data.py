from .models import AccessAttempt


def store_login_attempt(user_agent, ip_address, username,
                        http_accept, path_info, login_valid):
    """ Store the login attempt to the db. """
    AccessAttempt.objects.create(
        user_agent=user_agent,
        ip_address=ip_address,
        username=username,
        http_accept=http_accept,
        path_info=path_info,
        login_valid=login_valid,
    )
