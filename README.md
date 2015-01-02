django-defender
===============

A simple django reusable app that blocks people from brute forcing login
attempts. The goal is to make this as fast as possible, so that we do not
slow down the login attempts.

We will use a cache so that it doesn't have to hit the database in order to
check the database on each login attempt. The first version will be based on
Redis, but the goal is to make this configurable so that people can use what
they want for a backend, so it is configurable.

Version 0.1 will be very limited in features, it will only do a few things, but
the goal is to do those things very well, and have full unit tests with docs.

Build status
------------

[![Build Status](https://travis-ci.org/kencochrane/django-defender.svg)](https://travis-ci.org/kencochrane/django-defender)

[![Coverage Status](https://img.shields.io/coveralls/kencochrane/django-defender.svg)](https://coveralls.io/r/kencochrane/django-defender)

Goals for 0.1
=============

- Log all login attempts to the database
- support for reverse proxies with different headers for IP addresses
- rate limit based on:
    - username
    - ip address
- use redis for the blacklist
- configuration
    - redis server
        - host
        - port
        - database
        - password
        - key_prefix
    - block length
    - number of incorrect attempts before block
- 100% code coverage
- full documentation
- admin pages
    - list of blocked usernames and ip's
    - ability to unblock people
    - list of recent login attempts
    - search by username for recent login attempts

Long term goals
===============

- pluggable backends, so people can use something other then redis.
- email users when their account is blocked
- add a whitelist for username and ip's that we will never block (admin's, etc)
- add a permanent black list
    - ip address
- scan for known proxy ip's and don't block requests coming from those
(improve the chances that a good IP is blocked)
- add management command to prune old (configurable) login attempts.

Why not django-axes
===================

django-axes is great but it puts everything in the database, and this causes
a bottle neck when you have a lot of data. It slows down the auth requests by
as much as 200-300ms. This might not be much for some sites, but for others it
is too long.

This started out as a fork of django-axes, and is using as much of their code
as possible, and removing the parts not needed, and speeding up the lookups
to improve the login.

requirements
============

- django: 1.4.x, 1.6.x, 1.7.x
- redis
- python: 2.6.x, 2.7.x, 3.2.x, 3.3.x, 3.4.x, PyPy

How it works
============

1. When someone tries to login, we first check to see if they are currently
blocked. We check the username they are trying to use, as well as the IP
address. If they are blocked, goto step 10. If not blocked go to step 2.

2. They are not blocked, so we check to see if the login was valid. If valid
go to step 20. If not valid go to step 3.

3. Login attempt wasn't valid. Add their username and IP address for this
attempt to the cache. If this brings them over the limit, add them to the
blocked list, and then goto step 10. If not over the limit goto step 4.

4. login was invalid, but not over the limit. Send them back to the login screen
to try again.


10. User is blocked: Send them to the blocked page, telling them they are
blocked, and give an estimate on when they will be unblocked.

20. Login is valid. Reset any failed login attempts, and forward to their
destination.


Cache backend:
==============

- IP_attempts (count, TTL)
- username_attempts (count, TTL)
- ip_blocks (list) # how to expire when in a list?
- username_blocks (list) # how to expire item in the list?

cache keys:
-----------

- prefix:failed:ip:[ip] (count, TTL)
- prefix:failed:username:[username] (count, TTL)
- prefix:blocked:ip:[ip] (true, TTL)
- prefix:blocked:username:[username] (true, TTL)

Rate limiting Example
---------------------
```
# example of how to do rate limiting by IP
# assuming it is 10 requests being the limit
# this assumes there is a DECAY of DECAY_TIME
# to remove invalid logins after a set number of time
# For every incorrect login, we reset the block time.

FUNCTION LIMIT_API_CALL(ip)
current = LLEN(ip)
IF current > 10 THEN
    ERROR "too many requests per second"
ELSE
    MULTI
        RPUSH(ip, ip)
        EXPIRE(ip, DECAY_TIME)
    EXEC
END
```

Installing Django-defender
==========================

Download code, and run setup.

TODO: add to pypi once stable.

```
    $ python setup.py install

    or

    $ pip install -e git+http://github.com/kencochrane/django-defender.git#egg=django_defender-dev

```

First of all, you must add this project to your list of ``INSTALLED_APPS`` in
``settings.py``::

```
INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    ...
    'defender',
    ...
    )
```

Next, install the ``FailedLoginMiddleware`` middleware::

```
    MIDDLEWARE_CLASSES = (
        'django.middleware.common.CommonMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'defender.middleware.FailedLoginMiddleware'
        )
```

Run ``python manage.py syncdb``.  This creates the appropriate tables in your database
that are necessary for operation.


Customizing Defender
--------------------

You have a couple options available to you to customize ``django-defender`` a bit.
These should be defined in your ``settings.py`` file.

* ``DEFENDER_LOGIN_FAILURE_LIMIT``: The number of login attempts allowed before a
record is created for the failed logins.  Default: ``3``
* ``DEFENDER_USE_USER_AGENT``: If ``True``, lock out / log based on an IP address
AND a user agent.  This means requests from different user agents but from
the same IP are treated differently.  Default: ``False``
* ``DEFENDER_COOLOFF_TIME``: If set, defines a period of inactivity after which
old failed login attempts will be forgotten. An integer, will be interpreted as a
number of seconds.  Default: ``300``
* ``DEFENDER_LOCKOUT_TEMPLATE``: If set, specifies a template to render when a
user is locked out. Template receives cooloff_time and failure_limit as
context variables. Default: ``None``
* ``DEFENDER_USERNAME_FORM_FIELD``: the name of the form field that contains your
users usernames. Default: ``username``
* ``DEFENDER_REVERSE_PROXY_HEADER``: the name of the http header with your
reverse proxy IP address  Default: ``HTTP_X_FORWARDED_FOR``
* ``DEFENDER_CACHE_PREFIX``: The cache prefix for your defender keys.
Default: ``defender``
* ``DEFENDER_LOCKOUT_URL``: The URL you want to redirect to if someone is
locked out.
* ``DEFENDER_REDIS_URL``: the redis url for defender.
Default: ``redis://localhost:6379/0``
(Example with password: ``redis://:mypassword@localhost:6379/0``)


Running Tests
=============

Tests can be run, after you clone the repository and having django installed,
    like:

```
$ PYTHONPATH=$PYTHONPATH:$PWD django-admin.py test defender --settings=defender.test_settings
```
