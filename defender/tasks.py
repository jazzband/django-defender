from .data import store_login_attempt
from . import config


def add_login_attempt_task(
    user_agent, ip_address, username, http_accept, path_info, login_valid
):
    """ Create a record for the login attempt """
    store_login_attempt(
        user_agent, ip_address, username, http_accept, path_info, login_valid
    )

if config.USE_CELERY:
    from celery import shared_task
    add_login_attempt_task = shared_task(add_login_attempt_task)
