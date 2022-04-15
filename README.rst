
django-defender
===============

.. image:: https://jazzband.co/static/img/badge.svg
   :target: https://jazzband.co/
   :alt: Jazzband

.. image:: https://img.shields.io/pypi/pyversions/django-defender.svg
    :alt: Supported Python versions
    :target: https://pypi.org/project/django-defender/

.. image:: https://img.shields.io/pypi/djversions/django-defender.svg
   :target: https://pypi.org/project/django-defender/
   :alt: Supported Django versions

.. image:: https://github.com/jazzband/django-defender/workflows/Test/badge.svg
   :target: https://github.com/jazzband/django-defender/actions
   :alt: GitHub Actions

.. image:: https://codecov.io/gh/jazzband/django-defender/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/jazzband/django-defender
   :alt: Coverage

.. image:: https://readthedocs.org/projects/django-defender/badge/?version=latest
   :alt: Documentation Status
   :target: https://django-defender.readthedocs.io/en/latest/?badge=latest


A simple Django reusable app that blocks people from brute forcing login
attempts. The goal is to make this as fast as possible, so that we do not
slow down the login attempts.

We will use a cache so that it doesn't have to hit the database in order to
check the database on each login attempt. The first version will be based on
Redis, but the goal is to make this configurable so that people can use whatever
backend best fits their needs.


Sites using django-defender
---------------------------

If you are using defender on your site, submit a PR to add to the list.

* https://hub.docker.com
* https://www.mycosbuilder.com


Documentation
-------------

Documentation is available on Read the Docs:

https://django-defender.readthedocs.io


Features
--------

* Log all login attempts to the database
* Support for reverse proxies with different headers for IP addresses
* Rate limit based on

    * Username
    * IP address

* Use Redis for the blacklist
* Configuration

    * Redis server

        * Host
        * Port
        * Database
        * Password
        * Key prefix

    * Block length

    * Number of incorrect attempts before block

* 95% code coverage
* Full documentation
* Ability to store login attempts to the database
* Management command to clean up login attempts database table
* Admin pages

    * List of blocked usernames and IP addresses
    * List of recent login attempts
    * Ability to unblock people

* Can be easily adapted to custom authentication method.
* Signals are sent when blocking username or IP


Admin pages
***********

.. image:: https://cloud.githubusercontent.com/assets/261601/5950540/8895b570-a729-11e4-9dc3-6b00e46c8043.png
   :target: https://cloud.githubusercontent.com/assets/261601/5950540/8895b570-a729-11e4-9dc3-6b00e46c8043.png
   :alt: alt tag

.. image:: https://cloud.githubusercontent.com/assets/261601/5950541/88a35194-a729-11e4-981b-3a55b44ef9d5.png
   :target: https://cloud.githubusercontent.com/assets/261601/5950541/88a35194-a729-11e4-981b-3a55b44ef9d5.png
   :alt: alt tag


Requirements
------------

* Python: 3.7, 3.8, 3.9, 3.10, PyPy
* Django: 3.x, 4.x
* Redis


Installation
------------

Download code, and run setup in one of the following ways depending on the method.

To install the production ready version from PyPI:

.. code-block:: bash

   pip install django-defender

To install the development version from source code after download:

.. code-block:: bash

   python setup.py install

To install the master branch development version from the GitHub repository:

.. code-block:: bash

   pip install -e git+http://github.com/kencochran django-defender.git#egg=django_defender-dev

First of all, you must add this project to your list of ``INSTALLED_APPS`` in
``settings.py``

.. code-block:: python

   INSTALLED_APPS = [
       'django.contrib.admin',
       'django.contrib.auth',
       'django.contrib.contenttypes',
       'django.contrib.sessions',
       'django.contrib.sites',
       # ...
       'defender',
       # ...
   ]

Next, install the ``FailedLoginMiddleware`` middleware

.. code-block:: python

   MIDDLEWARE_CLASSES = [
       'django.middleware.common.CommonMiddleware',
       'django.contrib.sessions.middleware.SessionMiddleware',
       'django.contrib.auth.middleware.AuthenticationMiddleware',
       'defender.middleware.FailedLoginMiddleware',
   ]

If you want to manage the blocked users via the Django admin, then add the
following to your ``urls.py``

.. code-block:: python

   urlpatterns = [
       path('admin/', admin.site.urls), # normal admin
       path('admin/defender/', include('defender.urls')), # defender admin
       # your own patterns follow...
   ]


Migrations
**********

You will need to create tables in your database that are necessary
for operation.

.. code-block:: bash

   python manage.py migrate defender


Management commands
*******************

``cleanup_django_defender``

If you have a website with a lot of traffic, the AccessAttempts table will get
full pretty quickly. If you don't need to keep the data for auditing purposes
there is a management command to help you keep it clean.

It will look at your ``DEFENDER_ACCESS_ATTEMPT_EXPIRATION`` setting to determine
which records will be deleted. Default if not specified, is 24 hours.

.. code-block:: bash

   $ python manage.py cleanup_django_defender

You can set this up as a daily or weekly cron job to keep the table size down.

.. code-block:: bash

   # run at 12:24 AM every morning.
   24 0 * * * /usr/bin/python manage.py cleanup_django_defender >> /var/log/django_defender_cleanup.log


Long term goals
---------------

* Pluggable backends, so people can use something other than Redis
* Email users when their account is blocked
* Add a whitelist for username and ip's that we will never block (admin's, etc)
* Add a permanent black list for IP addresses
* Scan for known proxy IPs and do not block requests coming from those
  (improve the chances that a good IP is blocked)
* Add management command to prune old (configurable) login attempts.


Performance
***********

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


Load testing
************

In order to make sure we cover all the different types of logins, in our load
test we need to have more then one test.

#. All success: We will do a load test with nothing but successful logins.

#. Mixed: some success some failure: We will load test with some successful logins and some failures to see how the failure effect the performance.

#. All Failures: We will load test with all failure logins and see the difference in performance.

We will need a sample application that we can use for the load test, with the
only difference is the configuration where we either load defender, axes, or
none of them.

We can use a hosted load testing service, or something like jmeter. Either way
we need to be consistent for all of the tests. If we use jmeter, we should have
our jmeter configuration for others to run the tests on their own.


Results of load tests
*********************

We will post the results here. We will explain each test, and show the results
along with some charts.


Why not django-axes
-------------------

django-axes is great but it puts everything in the database, and this causes
a bottle neck when you have a lot of data. It slows down the auth requests by
as much as 200-300ms. This might not be much for some sites, but for others it
is too long.

This started out as a fork of django-axes, and is using as much of their code
as possible, and removing the parts not needed, and speeding up the lookups
to improve the login.


How django-defender works
-------------------------

#. When someone tries to login, we first check to see if they are currently
   blocked. We check the username they are trying to use, as well as the IP
   address. If they are blocked, goto step 5. If not blocked go to step 2.

#. They are not blocked, so we check to see if the login was valid. If valid
   go to step 6. If not valid go to step 3.

#. Login attempt wasn't valid. Add their username and IP address for this
   attempt to the cache. If this brings them over the limit, add them to the
   blocked list, and then goto step 5. If not over the limit goto step 4.

#. Login was invalid, but not over the limit. Send them back to the login screen
   to try again.

#. User is blocked: Send them to the blocked page, telling them they are
   blocked, and give an estimate on when they will be unblocked.

#. Login is valid. Reset any failed login attempts, and forward to their
   destination.


Cache backend
-------------

Defender uses the cache to save the failed attempts.


Cache keys
**********

Counters:

* prefix:failed:ip:[ip] (count, TTL)
* prefix:failed:username:[username] (count, TTL)

Booleans (if present it is blocked):

* prefix:blocked:ip:[ip] (true, TTL)
* prefix:blocked:username:[username] (true, TTL)


Customizing django-defender
---------------------------

You have a couple options available to you to customize ``django-defender`` a bit.
These should be defined in your ``settings.py`` file.

* ``DEFENDER_LOGIN_FAILURE_LIMIT``\ : Int: The number of login attempts allowed before a
  record is created for the failed logins.  [Default: ``3``\ ]
* ``DEFENDER_LOGIN_FAILURE_LIMIT_USERNAME``\ : Int: The number of login attempts allowed
  on a username before a record is created for the failed logins.  [Default: ``DEFENDER_LOGIN_FAILURE_LIMIT``\ ]
* ``DEFENDER_LOGIN_FAILURE_LIMIT_IP``\ : Int: The number of login attempts allowed
  from an IP before a record is created for the failed logins.  [Default: ``DEFENDER_LOGIN_FAILURE_LIMIT``\ ]
* ``DEFENDER_BEHIND_REVERSE_PROXY``\ : Boolean: Is defender behind a reverse proxy?
  [Default: ``False``\ ]
* ``DEFENDER_REVERSE_PROXY_HEADER``\ : String: the name of the http header with your
  reverse proxy IP address  [Default: ``HTTP_X_FORWARDED_FOR``\ ]
* ``DEFENDER_LOCK_OUT_BY_IP_AND_USERNAME``\ : Boolean: Locks a user out based on a combination of IP and Username.  This stops a user denying access to the application for all other users accessing the app from behind the same IP address. [Default: ``False``\ ]
* ``DEFENDER_DISABLE_IP_LOCKOUT``\ : Boolean: If this is True, it will not lockout the users IP address, it will only lockout the username. [Default: False]
* ``DEFENDER_DISABLE_USERNAME_LOCKOUT``\ : Boolean: If this is True, it will not lockout usernames, it will only lockout IP addresess. [Default: False]
* ``DEFENDER_COOLOFF_TIME``\ : Int: If set, defines a period of inactivity after which
  old failed login attempts will be forgotten. An integer, will be interpreted as a
  number of seconds. If ``0``\ , the locks will not expire. [Default: ``300``\ ]
* ``DEFENDER_LOCKOUT_TEMPLATE``\ : String:   [Default: ``None``\ ] If set, specifies a template to render when a user is locked out. Template receives the following context variables:

  * ``cooloff_time_seconds``\ : The cool off time in seconds
  * ``cooloff_time_minutes``\ : The cool off time in minutes
  * ``failure_limit``\ : The number of failures before you get blocked.

* ``DEFENDER_USERNAME_FORM_FIELD``\ : String: the name of the form field that contains your
  users usernames. [Default: ``username``\ ]
* ``DEFENDER_CACHE_PREFIX``\ : String: The cache prefix for your defender keys.
  [Default: ``defender``\ ]
* ``DEFENDER_LOCKOUT_URL``\ : String: The URL you want to redirect to if someone is
  locked out.
* ``DEFENDER_REDIS_URL``\ : String: the redis url for defender.
  [Default: ``redis://localhost:6379/0``\ ]
  (Example with password: ``redis://:mypassword@localhost:6379/0``\ )
* ``DEFENDER_REDIS_PASSWORD_QUOTE``\ : Boolean: if special character in redis password (like '@'), we can quote password ``urllib.parse.quote("password!@#")``, and set to True.
  [Default: ``False``\ ]
* ``DEFENDER_REDIS_NAME``\ : String: the name of your cache client on the CACHES django setting. If set, ``DEFENDER_REDIS_URL`` will be ignored.
  [Default: ``None``\ ]
* ``DEFENDER_STORE_ACCESS_ATTEMPTS``\ : Boolean: If you want to store the login
  attempt to the database, set to True. If False, it is not saved
  [Default: ``True``\ ]
* ``DEFENDER_USE_CELERY``\ : Boolean: If you want to use Celery to store the login
  attempt to the database, set to True. If False, it is saved inline.
  [Default: ``False``\ ]
* ``DEFENDER_ACCESS_ATTEMPT_EXPIRATION``\ : Int: Length of time in hours for how
  long to keep the access attempt records in the database before the management
  command cleans them up.
  [Default: ``24``\ ]
* ``DEFENDER_GET_USERNAME_FROM_REQUEST_PATH``\ : String: The import path of the function that access username from request.
  If you want to use custom function to access and process username from request - you can specify it here.
  [Default: ``defender.utils.username_from_request``\ ]


Adapting to other authentication methods
----------------------------------------

``defender`` can be used for authentication other than ``Django authentication system``.
E.g. if ``django-rest-framework`` authentication has to be protected from brute force attack, a custom authentication method can be implemented.

There's sample ``BasicAuthenticationDefender`` class based on ``djangorestframework.BasicAuthentication``\ :

.. code-block:: python

   import base64
   import binascii

   from django.utils.translation import gettext_lazy as _

   from rest_framework import HTTP_HEADER_ENCODING, exceptions
   from rest_framework.authentication import (
       BasicAuthentication,
       get_authorization_header,
   )

   from defender import utils
   from defender import config

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
           # add the failed attempt to Redis in case of a failed login or resets the attempt count in case of success
           utils.check_request(request,
                               login_unsuccessful=login_unsuccessful,
                               get_username=self.get_username_from_request)
           if login_unsuccessful:
               raise login_exception

           return response

To make it work add ``BasicAuthenticationDefender`` to ``DEFAULT_AUTHENTICATION_CLASSES`` above all other authentication methods in your ``settings.py``.

Adapting to other authentication methods :- django-rest-auth in djangorestframework
------------------------------------------------------------------------------------
``defender`` can be incorporated with the combination of ``django-rest-framework`` and ``django-rest-auth`` which can be used to authenticate users.

Reference
**********
* https://www.django-rest-framework.org/
* https://django-rest-auth.readthedocs.io/en/latest/

Below is a sample ``BasicAuthenticationDefender`` class based on ``rest_framework.authentication.TokenAuthentication`` which uses ``django-rest-auth`` library for user authentication.

.. code-block:: python

   import base64
   import binascii

   from django.conf import settings
   from django.contrib.auth import get_user_model, authenticate
   from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
   from django.contrib.auth.tokens import default_token_generator
   from django.utils.http import urlsafe_base64_decode as uid_decoder
   from django.utils.translation import ugettext_lazy as _
   from django.utils.encoding import force_text
   from rest_framework import serializers, exceptions, HTTP_HEADER_ENCODING
   from rest_framework.exceptions import ValidationError
   from defender import utils as defender_utils
   from defender import config
   from rest_framework.authentication import (
       get_authorization_header,
   )

   # Get the UserModel
   UserModel = get_user_model()

   class BasicAuthenticationDefender(serializers.Serializer):

      username = serializers.CharField(required=False, allow_blank=True)
      email = serializers.EmailField(required=False, allow_blank=True)
      password = serializers.CharField(style={'input_type': 'password'})

      def authenticate(self, **kwargs):
        request = self.context['request']

        if hasattr(settings, 'ACCOUNT_AUTHENTICATION_METHOD'):
            login_field = settings.ACCOUNT_AUTHENTICATION_METHOD
        else:
            login_field = 'username'
        userid = self.username_from_request(request, login_field)

        if defender_utils.is_already_locked(request, username=userid):
            detail = "You have attempted to login {failure_limit} times with no success. "
                     .format(
                         failure_limit=config.FAILURE_LIMIT,
                         cooloff_time_seconds=config.COOLOFF_TIME
                     )
            raise exceptions.AuthenticationFailed(_(detail))

        login_unsuccessful = False
        login_exception = None
        try:
            response = authenticate(request, **kwargs)
            if response == None:
                login_unsuccessful = True
                msg = _('Unable to log in with provided credentials.')
                # raise exceptions.ValidationError(msg)
                login_exception = exceptions.ValidationError(msg)
        except exceptions.AuthenticationFailed as e:
            login_unsuccessful = True
            login_exception = e

        defender_utils.add_login_attempt_to_db(request,
                                               login_valid=not login_unsuccessful,
                                               username=userid)

        user_not_blocked = defender_utils.check_request(request,
                                                        login_unsuccessful=login_unsuccessful,
                                                        username=userid)
        if user_not_blocked and not login_unsuccessful:
            return response

        raise login_exception

      def _validate_email(self, email, password):
        user = None

        if email and password:
            user = self.authenticate(email=email, password=password)
        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

      def _validate_username(self, username, password):
        user = None

        if username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        return user

      def _validate_username_email(self, username, email, password):
        user = None

        if email and password:
            user = self.authenticate(email=email, password=password)
        elif username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _('Must include either "username" or "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

      def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')

        user = None

        if 'allauth' in settings.INSTALLED_APPS:
            from allauth.account import app_settings

            # Authentication through email
            if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.EMAIL:
                user = self._validate_email(email, password)

            # Authentication through username
            elif app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.USERNAME:
                user = self._validate_username(username, password)

            # Authentication through either username or email
            else:
                user = self._validate_username_email(username, email, password)

        else:
            # Authentication without using allauth
            if email:
                try:
                    username = UserModel.objects.get(
                        email__iexact=email).username()
                except UserModel.DoesNotExist:
                    pass

            if username:
                user = self._validate_username_email(username, '', password)

        # Did we get back an active user?
        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            from allauth.account import app_settings
            if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError(
                        _('E-mail is not verified.'))

        attrs['user'] = user
        return attrs

      def username_from_request(self, request, login_field):
        user_data = request._data
        return user_data[login_field]

To make it work add ``BasicAuthenticationDefender`` to ``REST_AUTH_SERIALIZERS`` dictionary in your ``settings.py`` under the key ``LOGIN_SERIALIZER``.
For example, in your settings.py add the below line,

.. code-block:: python

   REST_AUTH_SERIALIZERS = {
       'LOGIN_SERIALIZER': '<path to your basic authentication defender python file>.BasicAuthenticationDefender',
   }

Adapting for password reset forms
---------------------------------

``defender`` can be adapted for Django’s ``PasswordResetView`` to prevent too many submissions.

We need to create some new views that subclass Django’s built-in ``LoginView``, ``PasswordResetView`` & ``PasswordResetConfirmView`` — then use these views in our ``urls.py`` as replacements for Django’s built-ins.

The views block based on email address submitted on the password reset view. This is different than the default implementation (which uses username), so we have to be careful to clean up after ourselves on sign-in & completed password reset.

.. code-block:: python

    from defender import utils as def_utils
    from django.contrib.auth import views as auth_views

    class UserSignIn(auth_views.LoginView):
        def form_valid(self, form):
            """Force clear all the cached Defender statues for the authenticated user’s email address."""
            super_valid = super().form_valid(form)
            def_utils.check_request(self.request, False, username=form.get_user().email)
            return super_valid

    class PasswordResetBruteForceProtectedView(auth_views.PasswordResetView):
        def get(self, request, *args, **kwargs):
            """Confirm the user isn’t already blocked by IP before showing the password reset view."""
            if def_utils.is_already_locked(request):
                return def_utils.lockout_response(request)
            return super().get(request, *args, **kwargs)

        def post(self, request, *args, **kwargs):
            """
            Confirm the user isn’t already blocked by IP before allowing form POST.
            
            Also, force log this form POST as a single entry in the Defender cache, against the submitted email address.
            """
            if def_utils.is_already_locked(request):
                return def_utils.lockout_response(request)
            def_utils.check_request(
                request, login_unsuccessful=True, username=request.POST.get("email")
            )
            return super().post(request, *args, **kwargs)


    class PasswordResetConfirmBruceForceProtectedView(auth_views.PasswordResetConfirmView):
        def get(self, request, *args, **kwargs):
            """Confirm the user isn’t already blocked by IP before showing the password confirm view."""
            if def_utils.is_already_locked(request):
                return def_utils.lockout_response(request)
            return super().get(request, *args, **kwargs)

        def post(self, request, *args, **kwargs):
            """Confirm the user isn’t already blocked by IP before allowing form POST for the password change confirmation."""
            if def_utils.is_already_locked(request):
                return def_utils.lockout_response(request)
            return super().post(request, *args, **kwargs)

        def form_valid(self, form):
            """Force clear all the cached Defender statues for the user’s email address after successfully changing their password."""
            super_valid = super().form_valid(form)
            def_utils.check_request(
                self.request, login_unsuccessful=False, username=self.user.email
            )
            return super_valid

Django signals
--------------

``django-defender`` will send signals when blocking a username or an IP address. To set up signal receiver functions:

.. code-block:: python

   from django.dispatch import receiver

   from defender import signals

   @receiver(signals.username_block)
   def username_blocked(username, **kwargs):
       print("%s was blocked!" % username)

   @receiver(signals.ip_block)
   def ip_blocked(ip_address, **kwargs):
       print("%s was blocked!" % ip_address)


Running tests
-------------

Tests can be run, after you clone the repository and having Django installed,
like:

.. code-block:: bash

   PYTHONPATH=$PYTHONPATH:$PWD django-admin test defender --settings=defender.test_settings

With Code coverage:

.. code-block:: bash

   PYTHONPATH=$PYTHONPATH:$PWD coverage run --source=defender $(which django-admin) test defender --settings=defender.test_settings


Releasing
---------

#. ``python setup.py sdist``
#. ``twine upload dist/*``
