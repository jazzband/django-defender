
Changes
=======

0.9.3
-----

- Drop Python 3.6 support from package specifiers.

0.9.2
-----

- Drop Python 3.6 support.
- Drop Django 3.1 support.
- Confirm support for Django 4.0
- Confirm support for Python 3.10
- Drop Django 2.2 support.

0.9.1
-----

- Fix failing tests for Django main development branch (Django 4.0) [@JonathanWillitts]

0.9.0
-----

- Move CI to GitHub Actions.
- Drop support for Django 3.0
- Add support for Django 3.2

0.8.0
-----

- FIX: Change setup.py to allow for Django 3.1.x versions [@s4ke]
- FIX: dynamic load celery [@balsagoth]
- FIX: Redis requirement updated [@flaviomartins]
- FIX: if special character in redis password, we can set DEFENDER_REDIS_PASSWORD_QUOTE to True, and use quote password [@calmkart]

0.7.0
-----

- Add support for Django 3.0 [@deeprave]
- Remove support from deprecated Python 3.4 and Django 2.0. [@aleksihakli]
- Add Read the Docs documentation. [@aleksihakli]
- Add support for Python 3.7, Python 3.8, PyPy3. [@aleksihakli]


0.6.2
-----

- Add and test support for Django 2.2 [@chrisledet]
- Add support for redis client 3.2.1 [@softinio]


0.6.1
-----

- Add redispy 3.2.0 compatibility [@nrth]


0.6.0
-----

- Remove Python 3.3 [@fr0mhell]
- Remove Django 1.8-1.10 [@fr0mhell]
- Add Celery v4 [@fr0mhell]
- Update travis config [@fr0mhell]
- Update admin URL [@fr0mhell]


0.5.5
-----

- Add new setting ``DEFENDER_GET_USERNAME_FROM_REQUEST_PATH`` for control how username is accessed from request [@andrewshkovskii]
- Add new argument ``get_username`` for ``decorators.watch_login`` to propagate ``get_username`` argument to other utils functions calls done in ``watch_login`` [@andrewshkovskii]


0.5.4
-----

- Add 2 new setting variables for more granular failure limit control [@williamboman]
- Add ssl option when instantiating StrictRedis [@mjrimrie]
- Send signals when blocking username or ip [@williamboman]


0.5.3
-----

- Remove mockredis as install requirement, make only test requirement [@blueyed]


0.5.2
-----

- Fix regex in 'unblock_username_view' to handle special symbols [@ruthus18]
- Fix django requires version for 1.11.x [@kencochrane]
- Remove hiredis dependency [@ericbuckley]
- Correctly get raw client when using django_redis cache. [@cburger]
- Replace django.core.urlresolvers with django.urls For Django 2.0 [@s-wirth]
- Add username kwarg for providing username directly rather than via callback arg [@williamboman]
- Only use the username if it is actually provided  [@cobusc]


0.5.1
-----

- Middleware fix for django >- 1.10 #93 [@Temeez]
- Force the username to lowercase #90 [@MattBlack85]


0.5.0
-----

- Better support for Django 1.11 [@dukebody]
- Add support to share redis config with django.core.cache [@Franr]
- Allow decoration of functions beyond the admin login [@MattBlack85]
- Doc improvements [@dukebody]
- Allow usernames with plus signs in unblock view [@dukebody]
- Code cleanup [@KenCochrane]


0.4.3
-----

- Flex version requirements for dependencies
- Better support for Django 1.10


0.4.2
-----

- Better support for Django 1.9


0.4.1
-----

- Minor refactor to make it easier to retrieve username.


0.4.0
-----

- Add ``DEFENDER_DISABLE_IP_LOCKOUT`` and added support for Python 3.5


0.3.2
-----

- Add ``DEFENDER_LOCK_OUT_BY_IP_AND_USERNAME``, and changed settings to support django 1.8.


0.3.1
-----

- Fix the management command name


0.3
---

- Add management command ``cleanup_django_defender`` to clean up access attempt table.
- Add ``DEFENDER_STORE_ACCESS_ATTEMPTS`` config to say if you want to store attempts to DB or not.
- Add ``DEFENDER_ACCESS_ATTEMPT_EXPIRATION`` config to specify how long to store the access attempt records in the db, before the management command cleans them up.
- Change the Django admin page to remove some filters which were making the page load slow with lots of login attempts in the database.

0.2.2
-----

- Another bug fix release for more missing files in distribution


0.2.1
-----

- Bug fixes for packing missing files


0.2
---

- Add fixes to include possible security issue


0.1
---

- Initial Version
