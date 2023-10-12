import urllib.parse as urlparse

import redis

from django.core.cache import caches
from django.core.cache.backends.base import InvalidCacheBackendError

from . import config

# Register database schemes in URLs.
urlparse.uses_netloc.append("redis")

INVALID_CACHE_ERROR_MSG = "The cache {} was not found on the django cache" " settings."


def get_redis_connection():
    """ Get the redis connection if not using mock """
    if config.MOCK_REDIS:  # pragma: no cover
        import mockredis

        return mockredis.mock_strict_redis_client()  # pragma: no cover
    elif config.DEFENDER_REDIS_NAME:  # pragma: no cover
        try:
            cache = caches[config.DEFENDER_REDIS_NAME]
        except InvalidCacheBackendError:
            raise KeyError(INVALID_CACHE_ERROR_MSG.format(config.DEFENDER_REDIS_NAME))
        # every redis backend implement it own way to get the low level client
        try:
            # redis_cache.RedisCache case (django-redis-cache package)
            return cache.get_master_client()
        except AttributeError:
            # django_redis.cache.RedisCache case (django-redis package)
            return cache.client.get_client(True)
    else:  # pragma: no cover)
        return redis.StrictRedis.from_url(config.DEFENDER_REDIS_URL)
