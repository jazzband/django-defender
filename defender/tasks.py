from .data import store_login_attempt

# not sure how to get this to look better. ideally we want to dynamically
# apply the celery decorator based on the USE_CELERY setting.

from celery import shared_task


@shared_task()
def add_login_attempt_task(user_agent, ip_address, username,
                           http_accept, path_info, login_valid):
    """ Create a record for the login attempt """
    store_login_attempt(user_agent, ip_address, username,
                        http_accept, path_info, login_valid)
