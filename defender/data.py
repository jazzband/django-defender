from datetime import datetime, timedelta

from defender import config
from .models import AccessAttempt
from django.db.models import Q


def store_login_attempt(
    user_agent, ip_address, username, http_accept, path_info, login_valid
):
    """ Store the login attempt to the db. """
    AccessAttempt.objects.create(
        user_agent=user_agent,
        ip_address=ip_address,
        username=username,
        http_accept=http_accept,
        path_info=path_info,
        login_valid=login_valid,
    )

def get_approx_account_lockouts_from_login_attempts(ip_address=None, username=None):
    """Get the approximate number of account lockouts in a period of ACCESS_ATTEMPT_EXPIRATION hours.
    This is approximate because we do not consider the time between these failed
    login attempts to be relevant.

    Args:
        ip_address (str, optional): IP address to search for. Can be used in conjunction with username for filtering when DISABLE_IP_LOCKOUT is False. Defaults to None.
        username (str, optional): Username to search for. Can be used in conjunction with ip_address for filtering when DISABLE_USERNAME_LOCKOUT is False. Defaults to None.

    Returns:
        int: The minimum of the count of logged failure attempts and the length of the LOCKOUT_COOLOFF_TIMES - 1, or 0 dependant on either configuration or argument parameters (ie. both ip_address and username being None).
    """

    # TODO: Possibly add logic to temporarily store this info in the cache
    # to help mitigate any potential performance impact this could have.

    if not config.STORE_ACCESS_ATTEMPTS or not (ip_address or username):
        # If we're not storing login attempts OR both ip_address and username are
        # None we should return 0.
        return 0

    q = Q(attempt_time__gte=datetime.now() - timedelta(hours=config.ACCESS_ATTEMPT_EXPIRATION))
    failure_limit = config.FAILURE_LIMIT
    if (ip_address and username and config.LOCKOUT_BY_IP_USERNAME \
        and not config.DISABLE_IP_LOCKOUT and not config.DISABLE_USERNAME_LOCKOUT
    ):
        q = q & Q(ip_address=ip_address) & Q(username=username)
    elif ip_address and not config.DISABLE_IP_LOCKOUT:
        failure_limit = config.IP_FAILURE_LIMIT
        q = q & Q(ip_address=ip_address)
    elif username and not config.DISABLE_USERNAME_LOCKOUT:
        failure_limit = config.USERNAME_FAILURE_LIMIT
        q = q & Q(username=username)
    else:
        # If we've made it this far and didn't hit one of the other if or elif
        # conditions, we're in an inappropriate context.
        raise Exception("Invalid state requested")

    return AccessAttempt.objects.filter(q).count() // failure_limit