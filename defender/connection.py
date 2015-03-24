import mockredis
import redis
try:
    import urlparse
except ImportError:  # pragma: no cover
    import urllib.parse as urlparse  # pragma: no cover # Python3 # pylint: disable=import-error,no-name-in-module,line-too-long

from . import config

# Register database schemes in URLs.
urlparse.uses_netloc.append("redis")


MOCKED_REDIS = mockredis.mock_strict_redis_client()


def get_redis_connection():
    """ Get the redis connection if not using mock """
    if config.MOCK_REDIS:  # pragma: no cover
        return MOCKED_REDIS  # pragma: no cover
    else:  # pragma: no cover
        redis_config = parse_redis_url(config.DEFENDER_REDIS_URL)
        return redis.StrictRedis(
            host=redis_config.get('HOST'),
            port=redis_config.get('PORT'),
            db=redis_config.get('DB'),
            password=redis_config.get('PASSWORD'))


def parse_redis_url(url):
    """Parses a redis URL."""

    # create config with some sane defaults
    redis_config = {
        "DB": 0,
        "PASSWORD": None,
        "HOST": "localhost",
        "PORT": 6379,
    }

    if not url:
        return redis_config

    url = urlparse.urlparse(url)
    # Remove query strings.
    path = url.path[1:]
    path = path.split('?', 2)[0]

    if path:
        redis_config.update({"DB": int(path)})
    if url.password:
        redis_config.update({"PASSWORD": url.password})
    if url.hostname:
        redis_config.update({"HOST": url.hostname})
    if url.port:
        redis_config.update({"PORT": int(url.port)})

    return redis_config
