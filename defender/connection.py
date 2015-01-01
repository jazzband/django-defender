import redis
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

from . import config

# Register database schemes in URLs.
urlparse.uses_netloc.append("redis")


def get_redis_connection():
    """ Get the redis connection """
    redis_config = parse_redis_url(config.DEFENDER_REDIS_URL)
    return redis.StrictRedis(
        host=redis_config.get('HOST'),
        port=redis_config.get('PORT'),
        db=redis_config.get('DB'),
        password=redis_config.get('PASSWORD'))


def parse_redis_url(url):
    """Parses a redis URL."""

    # create config with some sane defaults
    config = {
        "DB": 0,
        "PASSWORD": None,
        "HOST": "localhost",
        "PORT": 6379,
    }

    if not url:
        return config

    url = urlparse.urlparse(url)
    # Remove query strings.
    path = url.path[1:]
    path = path.split('?', 2)[0]

    if path:
        config.update({"DB": int(path)})
    if url.password:
        config.update({"PASSWORD": url.password})
    if url.hostname:
        config.update({"HOST": url.hostname})
    if url.port:
        config.update({"PORT": int(url.port)})

    return config
