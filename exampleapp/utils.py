from defender.utils import username_from_request


def strip_username_from_request(request):
    username = username_from_request(request)
    return username.strip() if username else username
