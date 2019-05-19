django-defender
===============

A simple Django reusable app that blocks people from brute forcing login
attempts. The goal is to make this as fast as possible, so that we do not
slow down the login attempts.

We will use a cache so that it doesn't have to hit the database in order to
check the database on each login attempt. The first version will be based on
Redis, but the goal is to make this configurable so that people can use whatever
backend best fits their needs.

Build status
------------

[![Build Status](https://travis-ci.org/kencochrane/django-defender.svg)](https://travis-ci.org/kencochrane/django-defender)  [![Coverage Status](https://img.shields.io/coveralls/kencochrane/django-defender.svg)](https://coveralls.io/r/kencochrane/django-defender)[![Code Health](https://landscape.io/github/kencochrane/django-defender/master/landscape.svg)](https://landscape.io/github/kencochrane/django-defender/master)

Sites using Defender:
=====================
If you are using defender on your site, submit a PR to add to the list.

- https://hub.docker.com
- https://www.mycosbuilder.com


Versions
========
- 0.6.1
  - added redispy 3.2.0 compatibility [@nrth]

- 0.6.0
  - remove Python 3.3 [@fr0mhell]
  - remove Django 1.8-1.10 [@fr0mhell]
  - add Celery v4 [@fr0mhell]
  - update travis config [@fr0mhell]
  - update admin URL [@fr0mhell]

- 0.5.5
  - Added new setting ``DEFENDER_GET_USERNAME_FROM_REQUEST_PATH`` for control how username is accessed from request [@andrewshkovskii]
  - Added new argument ``get_username`` for ``decorators.watch_login`` to propagate ``get_username`` argument to other utils functions calls done in ``watch_login`` [@andrewshkovskii]

- 0.5.4
  - Added 2 new setting variables for more granular failure limit control [@williamboman]
  - Added ssl option when instantiating StrictRedis [@mjrimrie]
  - Send signals when blocking username or ip [@williamboman]

- 0.5.3
  - Remove mockredis as install requirement, make only test requirement [@blueyed]

- 0.5.2
  - Fix regex in 'unblock_username_view' to handle special symbols [@ruthus18]
  - Fix django requires version for 1.11.x [@kencochrane]
  - remove hiredis dependency [@ericbuckley]
  - Correctly get raw client when using django_redis cache. [@cburger]
  - replace django.core.urlresolvers with django.urls For Django 2.0 [@s-wirth]
  - add username kwarg for providing username directly rather than via callback arg [@williamboman]
  - Only use the username if it is actually provided  [@cobusc]

- 0.5.1
  - Middleware fix for django >= 1.10 #93 [@Temeez]
  - Force the username to lowercase #90 [@MattBlack85]

- 0.5.0
  - Better support for Django 1.11 [@dukebody]
  - Added support to share redis config with django.core.cache [@Franr]
  - Allow decoration of functions beyond the admin login [@MattBlack85]
  - Doc improvements [@dukebody]
  - Allow usernames with plus signs in unblock view [@dukebody]
  - Code cleanup [@KenCochrane]
- 0.4.3 - Better Support for Django 1.10
- 0.4.2 - Better support for Django 1.9
- 0.4.1 - minor refactor to make it easier to retrieve username.
- 0.4.0 - added ``DEFENDER_DISABLE_IP_LOCKOUT`` and added support for Python 3.5
- 0.3.2 - added ``DEFENDER_LOCK_OUT_BY_IP_AND_USERNAME``, and changed settings
    to support django 1.8.
- 0.3.1 - fixed the management command name
- 0.3
    - Added management command ``cleanup_django_defender`` to clean up access
    attempt table.
    - Added ``DEFENDER_STORE_ACCESS_ATTEMPTS`` config to say if you want to
    store attempts to DB or not.
    - Added ``DEFENDER_ACCESS_ATTEMPT_EXPIRATION`` config to specify how long
    to store the access attempt records in the db, before the management command
    cleans them up.
    - changed the Django admin page to remove some filters which were making the
    page load slow with lots of login attempts in the database.
- 0.2.2 - bug fix add missing files to pypi package
- 0.2.1 - bug fix
- 0.2 - security fix for XFF headers
- 0.1.1 - setup.py fix
- 0.1 - initial release


Features
========

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
- 95% code coverage
- full documentation
- Ability to store login attempts to the database
- Management command to clean up login attempts database table
- admin pages
    - list of blocked usernames and ip's
    - ability to unblock people
    - list of recent login attempts
- Can be easily adapted to custom authentication method.
- Signals are sent when blocking username or IP

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

Performance:
============
The goal of defender is to make it as fast as possible so that it doesn't slow
down the login process. In order to make sure our goals are met we need a way
to test the application to make sure we are on the right track. The best
way to do this is to compare how fast a normal Django login takes with defender
and django-axes.

The normal django login, would be our baseline, and we expect it to be the
fastest of the 3 methods, because there are no additional checks happening.

The defender login would most likely be slower then the django login, and
hopefully faster then the django-axes login. The goal is to make it as little
of a difference between the regular raw login, and defender.

The django-axes login speed, will probably be the slowest of the three since it
does more checks and does a lot of database queries.

The best way to determine the speed of a login is to do a load test against an
application with each setup, and compare the login times for each type.

Types of Load tests
-------------------
In order to make sure we cover all the different types of logins, in our load
test we need to have more then one test.

1. All success:
  - We will do a load test with nothing but successful logins
2. Mixed: some success some failure:
  - We will load test with some successful logins and some failures to see how
  the failure effect the performance.
3. All Failures:
  - We will load test with all failure logins and see the difference in
  performance.

We will need a sample application that we can use for the load test, with the
only difference is the configuration where we either load defender, axes, or
none of them.

We can use a hosted load testing service, or something like jmeter. Either way
we need to be consistent for all of the tests. If we use jmeter, we should have
our jmeter configuration for others to run the tests on their own.

Results
-------
We will post the results here. We will explain each test, and show the results
along with some charts.


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

- django: 1.8.x, 1.9.x, 1.10.x, 1.11.x
- redis
- python: 2.7.x, 3.3.x, 3.4.x, 3.5.x, 3.6.x, PyPy

How it works
============

1. When someone tries to login, we first check to see if they are currently
blocked. We check the username they are trying to use, as well as the IP
address. If they are blocked, goto step 5. If not blocked go to step 2.

2. They are not blocked, so we check to see if the login was valid. If valid
go to step 6. If not valid go to step 3.

3. Login attempt wasn't valid. Add their username and IP address for this
attempt to the cache. If this brings them over the limit, add them to the
blocked list, and then goto step 5. If not over the limit goto step 4.

4. login was invalid, but not over the limit. Send them back to the login screen
to try again.

5. User is blocked: Send them to the blocked page, telling them they are
blocked, and give an estimate on when they will be unblocked.

6. Login is valid. Reset any failed login attempts, and forward to their
destination.


Cache backend:
==============

cache keys:
-----------

Counters:
- prefix:failed:ip:[ip] (count, TTL)
- prefix:failed:username:[username] (count, TTL)

Booleans (if present it is blocked):
- prefix:blocked:ip:[ip] (true, TTL)
- prefix:blocked:username:[username] (true, TTL)

Installing Django-defender
==========================

Download code, and run setup.

```
    $ pip install django-defender

    or

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

If you want to manage the blocked users via the Django admin, then add the
following to your ``urls.py``

```
urlpatterns = patterns(
    '',
    (r'^admin/', include(admin.site.urls)), # normal admin
    (r'^admin/defender/', include('defender.urls')), # defender admin
    # your own patterns follow…
)
```

Management Commands:
--------------------

``cleanup_django_defender``:

If you have a website with a lot of traffic, the AccessAttempts table will get
full pretty quickly. If you don't need to keep the data for auditing purposes
there is a management command to help you keep it clean.

It will look at your ``DEFENDER_ACCESS_ATTEMPT_EXPIRATION`` setting to determine
which records will be deleted. Default if not specified, is 24 hours.

```bash
$ python manage.py cleanup_django_defender
```

You can set this up as a daily or weekly cron job to keep the table size down.

```bash
# run at 12:24 AM every morning.
24 0 * * * /usr/bin/python manage.py cleanup_django_defender >> /var/log/django_defender_cleanup.log
```


Admin Pages:
------------
![alt tag](https://cloud.githubusercontent.com/assets/261601/5950540/8895b570-a729-11e4-9dc3-6b00e46c8043.png)

![alt tag](https://cloud.githubusercontent.com/assets/261601/5950541/88a35194-a729-11e4-981b-3a55b44ef9d5.png)

Database tables:
----------------

You will need to create tables in your database that are necessary
for operation.

```bash
python manage.py migrate defender
```

Customizing Defender
--------------------

You have a couple options available to you to customize ``django-defender`` a bit.
These should be defined in your ``settings.py`` file.

* ``DEFENDER_LOGIN_FAILURE_LIMIT``: Int: The number of login attempts allowed before a
record is created for the failed logins.  [Default: ``3``]
* ``DEFENDER_LOGIN_FAILURE_LIMIT_USERNAME``: Int: The number of login attempts allowed
on a username before a record is created for the failed logins.  [Default: ``DEFENDER_LOGIN_FAILURE_LIMIT``]
* ``DEFENDER_LOGIN_FAILURE_LIMIT_IP``: Int: The number of login attempts allowed
from an IP before a record is created for the failed logins.  [Default: ``DEFENDER_LOGIN_FAILURE_LIMIT``]
* ``DEFENDER_BEHIND_REVERSE_PROXY``: Boolean: Is defender behind a reverse proxy?
[Default: ``False``]
* ``DEFENDER_REVERSE_PROXY_HEADER``: String: the name of the http header with your
reverse proxy IP address  [Default: ``HTTP_X_FORWARDED_FOR``]
* ``DEFENDER_LOCK_OUT_BY_IP_AND_USERNAME``: Boolean: Locks a user out based on a combination of IP and Username.  This stops a user denying access to the application for all other users accessing the app from behind the same IP address. [Default: ``False``]
* ``DEFENDER_DISABLE_IP_LOCKOUT``: Boolean: If this is True, it will not lockout the users IP address, it will only lockout the username. [Default: False]
* ``DEFENDER_DISABLE_USERNAME_LOCKOUT``: Boolean: If this is True, it will not lockout usernames, it will only lockout IP addresess. [Default: False]
* ``DEFENDER_COOLOFF_TIME``: Int: If set, defines a period of inactivity after which
old failed login attempts will be forgotten. An integer, will be interpreted as a
number of seconds. If ``0``, the locks will not expire. [Default: ``300``]
* ``DEFENDER_LOCKOUT_TEMPLATE``: String:   [Default: ``None``] If set, specifies a template to render when a user is locked out. Template receives the following context variables:
   - ``cooloff_time_seconds``: The cool off time in seconds
   - ``cooloff_time_minutes``: The cool off time in minutes
   - ``failure_limit``: The number of failures before you get blocked.
* ``DEFENDER_USERNAME_FORM_FIELD``: String: the name of the form field that contains your
users usernames. [Default: ``username``]
* ``DEFENDER_CACHE_PREFIX``: String: The cache prefix for your defender keys.
[Default: ``defender``]
* ``DEFENDER_LOCKOUT_URL``: String: The URL you want to redirect to if someone is
locked out.
* ``DEFENDER_REDIS_URL``: String: the redis url for defender.
[Default: ``redis://localhost:6379/0``]
(Example with password: ``redis://:mypassword@localhost:6379/0``)
* ``DEFENDER_REDIS_NAME``: String: the name of your cache client on the CACHES django setting. If set, ``DEFENDER_REDIS_URL`` will be ignored.
[Default: ``None``]
* ``DEFENDER_STORE_ACCESS_ATTEMPTS``: Boolean: If you want to store the login
attempt to the database, set to True. If False, it is not saved
[Default: ``True``]
* ``DEFENDER_USE_CELERY``: Boolean: If you want to use Celery to store the login
attempt to the database, set to True. If False, it is saved inline.
[Default: ``False``]
* ``DEFENDER_ACCESS_ATTEMPT_EXPIRATION``: Int: Length of time in hours for how
long to keep the access attempt records in the database before the management
command cleans them up.
[Default: ``24``]
* ``DEFENDER_GET_USERNAME_FROM_REQUEST_PATH``: String: The import path of the function that access username from request.
If you want to use custom function to access and process username from request - you can specify it here.
[Default: ``defender.utils.username_from_request``]

Adapting to other authentication method
--------------------

`defender` can be used for authentication other than `Django authentication system`.
E.g. if `django-rest-framework` authentication has to be protected from brute force attack, a custom authentication method can be implemented.

There's sample `BasicAuthenticationDefender` class based on `djangorestframework.BasicAuthentication`:

```python
import base64
import binascii

from defender import utils
from defender import config
from django.utils.translation import ugettext_lazy as _

from rest_framework import HTTP_HEADER_ENCODING, exceptions

from rest_framework.authentication import (
    BasicAuthentication,
    get_authorization_header,
    )


class BasicAuthenticationDefender(BasicAuthentication):

    def get_username_from_request(self, request):
        auth = get_authorization_header(request).split()
        return base64.b64decode(auth[1]).decode(HTTP_HEADER_ENCODING).partition(':')[0]

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'basic':
            return None

        if len(auth) == 1:
            msg = _('Invalid basic header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid basic header. Credentials string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        if utils.is_already_locked(request, get_username=self.get_username_from_request):
            detail = "You have attempted to login {failure_limit} times, with no success." \
                     "Your account is locked for {cooloff_time_seconds} seconds" \
                     "".format(
                        failure_limit=config.FAILURE_LIMIT,
                        cooloff_time_seconds=config.COOLOFF_TIME
                     )
            raise exceptions.AuthenticationFailed(_(detail))

        try:
            auth_parts = base64.b64decode(auth[1]).decode(HTTP_HEADER_ENCODING).partition(':')
        except (TypeError, UnicodeDecodeError, binascii.Error):
            msg = _('Invalid basic header. Credentials not correctly base64 encoded.')
            raise exceptions.AuthenticationFailed(msg)

        userid, password = auth_parts[0], auth_parts[2]
        login_unsuccessful = False
        login_exception = None
        try:
            response = self.authenticate_credentials(userid, password)
        except exceptions.AuthenticationFailed as e:
            login_unsuccessful = True
            login_exception = e

        utils.add_login_attempt_to_db(request,
                                      login_valid=not login_unsuccessful,
                                      get_username=self.get_username_from_request)

        user_not_blocked = utils.check_request(request,
                                               login_unsuccessful=login_unsuccessful,
                                               get_username=self.get_username_from_request)
        if user_not_blocked and not login_unsuccessful:
            return response

        raise login_exception

```

To make it works add `BasicAuthenticationDefender` to `DEFAULT_AUTHENTICATION_CLASSES` above all other authentication methods in your `settings.py`.


Django Signals
--------------------

`django-defender` will send signals when blocking a username or an IP address. To set up signal receiver functions:

```python
from django.dispatch import receiver
from defender import signals

@receiver(signals.username_block)
def username_blocked(username, **kwargs):
    print("%s was blocked!" % username)

@receiver(signals.ip_block)
def ip_blocked(ip_address, **kwargs):
    print("%s was blocked!" % ip_address)

```

Running Tests
=============

Tests can be run, after you clone the repository and having Django installed,
like:

```
$ PYTHONPATH=$PYTHONPATH:$PWD django-admin.py test defender --settings=defender.test_settings
```

With Code coverage:

```
PYTHONPATH=$PYTHONPATH:$PWD coverage run --source=defender $(which django-admin.py) test defender --settings=defender.test_settings
```

How to release
==============
1. python setup.py sdist
2. twine upload dist/*
