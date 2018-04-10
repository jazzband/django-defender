from django.core.cache import caches
from django.core.cache.backends.base import InvalidCacheBackendError

import redis
try:
    import urlparse
except ImportError:  # pragma: no cover
    import urllib.parse as urlparse  # pragma: no cover # Python3 # pylint: disable=import-error,no-name-in-module,line-too-long

from . import config

# Register database schemes in URLs.
urlparse.uses_netloc.append("redis")

INVALID_CACHE_ERROR_MSG = 'The cache {} was not found on the django cache' \
                          ' settings.'


def get_redis_connection():
    """ Get the redis connection if not using mock """
    if config.MOCK_REDIS:  # pragma: no cover
        import mockredis
        return mockredis.mock_strict_redis_client()  # pragma: no cover
    elif config.DEFENDER_REDIS_NAME:  # pragma: no cover
        try:
            cache = caches[config.DEFENDER_REDIS_NAME]
        except InvalidCacheBackendError:
            raise KeyError(INVALID_CACHE_ERROR_MSG.format(
                config.DEFENDER_REDIS_NAME))
        # every redis backend implement it own way to get the low level client
        try:
            # redis_cache.RedisCache case (django-redis-cache package)
            return cache.get_master_client()
        except AttributeError:
            # django_redis.cache.RedisCache case (django-redis package)
            return cache.client.get_client(True)
    else:  # pragma: no cover
        redis_config = parse_redis_url(config.DEFENDER_REDIS_URL)
        return redis.StrictRedis(
            host=redis_config.get('HOST'),
            port=redis_config.get('PORT'),
            db=redis_config.get('DB'),
            password=redis_config.get('PASSWORD'),
            ssl=redis_config.get('SSL'))



def parse_redis_url(url):
    """Parses a redis URL."""

    # create config with some sane defaults
    redis_config = {
        "DB": 0,
        "PASSWORD": None,
        "HOST": "localhost",
        "PORT": 6379,
        "SSL": False
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
    if url.scheme in ['https', 'rediss']:
        redis_config.update({"SSL": True})

    return redis_config
