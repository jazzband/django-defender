import random
import string
import time
from distutils.version import StrictVersion

from mock import patch

from django import get_version
from django.contrib.auth.models import User
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.db import SessionStore
from django.core.urlresolvers import NoReverseMatch
from django.core.urlresolvers import reverse
from django.http import HttpRequest
from django.test.client import RequestFactory

from . import utils
from . import config
from .connection import parse_redis_url, get_redis_connection
from .models import AccessAttempt
from .test import DefenderTestCase, DefenderTransactionTestCase

# Django >= 1.7 compatibility
try:
    LOGIN_FORM_KEY = '<form action="/admin/login/" method="post"'
    ' id="login-form">'
    ADMIN_LOGIN_URL = reverse('admin:login')
except NoReverseMatch:
    ADMIN_LOGIN_URL = reverse('admin:index')
    LOGIN_FORM_KEY = 'this_is_the_login_form'

DJANGO_VERSION = StrictVersion(get_version())

VALID_USERNAME = VALID_PASSWORD = 'valid'


class AccessAttemptTest(DefenderTestCase):
    """ Test case using custom settings for testing
    """
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'
    PERMANENT_LOCKED_MESSAGE = (
        LOCKED_MESSAGE + '  Contact an admin to unlock your account.'
    )

    def _get_random_str(self):
        """ Returns a random str """
        chars = string.ascii_uppercase + string.digits

        return ''.join(random.choice(chars) for x in range(20))

    def _login(self, username=None, password=None, user_agent='test-browser',
               remote_addr='127.0.0.1'):
        """ Login a user. If the username or password is not provided
        it will use a random string instead. Use the VALID_USERNAME and
        VALID_PASSWORD to make a valid login.
        """
        if username is None:
            username = self._get_random_str()

        if password is None:
            password = self._get_random_str()

        response = self.client.post(ADMIN_LOGIN_URL, {
            'username': username,
            'password': password,
            LOGIN_FORM_KEY: 1,
        }, HTTP_USER_AGENT=user_agent, REMOTE_ADDR=remote_addr)

        return response

    def setUp(self):
        """ Create a valid user for login
        """
        self.user = User.objects.create_superuser(
            username=VALID_USERNAME,
            email='test@example.com',
            password=VALID_PASSWORD,
        )

    def test_data_integrity_of_get_blocked_ips(self):
        """ Test whether data retrieved from redis via
        get_blocked_ips() is the same as the data saved
        """
        data_in = ['127.0.0.1', '4.2.2.1']
        for ip in data_in:
            utils.block_ip(ip)
        data_out = utils.get_blocked_ips()
        self.assertEqual(sorted(data_in), sorted(data_out))

        # send in None, should have same values.
        utils.block_ip(None)
        data_out = utils.get_blocked_ips()
        self.assertEqual(sorted(data_in), sorted(data_out))

    def test_data_integrity_of_get_blocked_usernames(self):
        """ Test whether data retrieved from redis via
        get_blocked_usernames() is the same as the data saved
        """
        data_in = ['foo', 'bar']
        for username in data_in:
            utils.block_username(username)
        data_out = utils.get_blocked_usernames()
        self.assertEqual(sorted(data_in), sorted(data_out))

        # send in None, should have same values.
        utils.block_username(None)
        data_out = utils.get_blocked_usernames()
        self.assertEqual(sorted(data_in), sorted(data_out))

    def test_login_get(self):
        """ visit the login page """
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEqual(response.status_code, 200)

    def test_failure_limit_by_ip_once(self):
        """ Tests the login lock by ip when trying to login
        one more time than failure limit
        """
        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_failure_limit_by_ip_many(self):
        """ Tests the login lock by ip when trying to
        login a lot of times more than failure limit
        """
        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        for i in range(0, random.randrange(1, 10)):
            # try to log in a bunch of times
            response = self._login()
            self.assertContains(response, self.LOCKED_MESSAGE)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_failure_limit_by_username_once(self):
        """ Tests the login lock by username when trying to login
        one more time than failure limit
        """
        for i in range(0, config.FAILURE_LIMIT):
            ip = '74.125.239.{0}.'.format(i)
            response = self._login(username=VALID_USERNAME, remote_addr=ip)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_valid_login(self):
        """ Tests a valid login for a real username
        """
        response = self._login(username=VALID_USERNAME,
                               password=VALID_PASSWORD)
        self.assertNotContains(response, LOGIN_FORM_KEY, status_code=302)

    def test_reset_after_valid_login(self):
        """ Tests the counter gets reset after a valid login
        """
        for i in range(0, config.FAILURE_LIMIT):
            self._login(username=VALID_USERNAME)

        # now login with a valid username and password
        self._login(username=VALID_USERNAME, password=VALID_PASSWORD)

        # and we should be able to try again without hitting the failure limit
        response = self._login(username=VALID_USERNAME)
        self.assertNotContains(response, self.LOCKED_MESSAGE)

    def test_blocked_ip_cannot_login(self):
        """ Test an user with blocked ip cannot login with another username
        """
        for i in range(0, config.FAILURE_LIMIT + 1):
            response = self._login(username=VALID_USERNAME)

        # try to login with a different user
        response = self._login(username='myuser')
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_blocked_username_cannot_login(self):
        """ Test an user with blocked username cannot login using
        another ip
        """
        for i in range(0, config.FAILURE_LIMIT + 1):
            ip = '74.125.239.{0}.'.format(i)
            response = self._login(username=VALID_USERNAME, remote_addr=ip)

        # try to login with a different ip
        response = self._login(username=VALID_USERNAME, remote_addr='8.8.8.8')
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_cooling_off(self):
        """ Tests if the cooling time allows a user to login
        """
        self.test_failure_limit_by_ip_once()
        # Wait for the cooling off period
        time.sleep(config.COOLOFF_TIME)

        if config.MOCK_REDIS:
            # mock redis require that we expire on our own
            get_redis_connection().do_expire()  # pragma: no cover
        # It should be possible to login again, make sure it is.
        self.test_valid_login()

    def test_cooling_off_for_trusted_user(self):
        """ Test the cooling time for a trusted user
        """
        # Try the cooling off time
        self.test_cooling_off()

    def test_long_user_agent_valid(self):
        """ Tests if can handle a long user agent
        """
        long_user_agent = 'ie6' * 1024
        response = self._login(username=VALID_USERNAME, password=VALID_PASSWORD,
                               user_agent=long_user_agent)
        self.assertNotContains(response, LOGIN_FORM_KEY, status_code=302)

    @patch('defender.config.BEHIND_REVERSE_PROXY', True)
    @patch('defender.config.REVERSE_PROXY_HEADER', 'HTTP_X_FORWARDED_FOR')
    def test_get_ip_reverse_proxy(self):
        """ Tests if can handle a long user agent
        """
        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META['HTTP_X_FORWARDED_FOR'] = '192.168.24.24'
        self.assertEqual(utils.get_ip(request), '192.168.24.24')

        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META['REMOTE_ADDR'] = '24.24.24.24'
        self.assertEqual(utils.get_ip(request), '24.24.24.24')

    def test_get_ip(self):
        """ Tests if can handle a long user agent
        """
        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        self.assertEqual(utils.get_ip(request), '127.0.0.1')

    def test_long_user_agent_not_valid(self):
        """ Tests if can handle a long user agent with failure
        """
        long_user_agent = 'ie6' * 1024
        for i in range(0, config.FAILURE_LIMIT + 1):
            response = self._login(user_agent=long_user_agent)

        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_reset_ip(self):
        """ Tests if can reset an ip address
        """
        # Make a lockout
        self.test_failure_limit_by_ip_once()

        # Reset the ip so we can try again
        utils.reset_failed_attempts(ip_address='127.0.0.1')

        # Make a login attempt again
        self.test_valid_login()

    @patch('defender.config.LOCKOUT_URL', 'http://localhost/othe/login/')
    def test_failed_login_redirect_to_URL(self):
        """ Test to make sure that after lockout we send to the correct
        redirect URL """

        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now, check redirect make sure it is valid.
        response = self._login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], 'http://localhost/othe/login/')

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], 'http://localhost/othe/login/')

    @patch('defender.config.LOCKOUT_URL', '/o/login/')
    def test_failed_login_redirect_to_URL_local(self):
        """ Test to make sure that after lockout we send to the correct
        redirect URL """

        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # RFC 7231 allows relative URIs in Location header.
        # Django from version 1.9 is support this:
        # https://docs.djangoproject.com/en/1.9/releases/1.9/#http-redirects-no-longer-forced-to-absolute-uris
        lockout_url = 'http://testserver/o/login/'
        if DJANGO_VERSION >= StrictVersion('1.9'):
            lockout_url = '/o/login/'

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now, check redirect make sure it is valid.
        response = self._login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], lockout_url)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], lockout_url)

    @patch('defender.config.LOCKOUT_TEMPLATE', 'defender/lockout.html')
    def test_failed_login_redirect_to_template(self):
        """ Test to make sure that after lockout we send to the correct
        template """

        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now, check template make sure it is valid.
        response = self._login()
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'defender/lockout.html')

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'defender/lockout.html')

    @patch('defender.config.COOLOFF_TIME', 0)
    def test_failed_login_no_cooloff(self):
        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now, check redirect make sure it is valid.
        response = self._login()
        self.assertContains(response, self.PERMANENT_LOCKED_MESSAGE)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, self.PERMANENT_LOCKED_MESSAGE)

    def test_login_attempt_model(self):
        """ test the login model"""

        response = self._login()
        self.assertContains(response, LOGIN_FORM_KEY)
        self.assertEqual(AccessAttempt.objects.count(), 1)
        self.assertIsNotNone(str(AccessAttempt.objects.all()[0]))

    def test_is_valid_ip(self):
        """ Test the is_valid_ip() method """
        self.assertEqual(utils.is_valid_ip('192.168.0.1'), True)
        self.assertEqual(utils.is_valid_ip('130.80.100.24'), True)
        self.assertEqual(utils.is_valid_ip('8.8.8.8'), True)
        self.assertEqual(utils.is_valid_ip('127.0.0.1'), True)
        self.assertEqual(utils.is_valid_ip('fish'), False)
        self.assertEqual(utils.is_valid_ip(None), False)
        self.assertEqual(utils.is_valid_ip(''), False)
        self.assertEqual(utils.is_valid_ip('0x41.0x41.0x41.0x41'), False)
        self.assertEqual(utils.is_valid_ip('192.168.100.34.y'), False)
        self.assertEqual(
            utils.is_valid_ip('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), True)
        self.assertEqual(
            utils.is_valid_ip('2001:db8:85a3:0:0:8a2e:370:7334'), True)
        self.assertEqual(
            utils.is_valid_ip('2001:db8:85a3::8a2e:370:7334'), True)
        self.assertEqual(
            utils.is_valid_ip('::ffff:192.0.2.128'), True)
        self.assertEqual(
            utils.is_valid_ip('::ffff:8.8.8.8'), True)

    def test_parse_redis_url(self):
        """ test the parse_redis_url method """
        # full regular
        conf = parse_redis_url("redis://user:password@localhost2:1234/2")
        self.assertEqual(conf.get('HOST'), 'localhost2')
        self.assertEqual(conf.get('DB'), 2)
        self.assertEqual(conf.get('PASSWORD'), 'password')
        self.assertEqual(conf.get('PORT'), 1234)

        # full non local
        conf = parse_redis_url("redis://user:pass@www.localhost.com:1234/2")
        self.assertEqual(conf.get('HOST'), 'www.localhost.com')
        self.assertEqual(conf.get('DB'), 2)
        self.assertEqual(conf.get('PASSWORD'), 'pass')
        self.assertEqual(conf.get('PORT'), 1234)

        # no user name
        conf = parse_redis_url("redis://password@localhost2:1234/2")
        self.assertEqual(conf.get('HOST'), 'localhost2')
        self.assertEqual(conf.get('DB'), 2)
        self.assertEqual(conf.get('PASSWORD'), None)
        self.assertEqual(conf.get('PORT'), 1234)

        # no user name 2 with colon
        conf = parse_redis_url("redis://:password@localhost2:1234/2")
        self.assertEqual(conf.get('HOST'), 'localhost2')
        self.assertEqual(conf.get('DB'), 2)
        self.assertEqual(conf.get('PASSWORD'), 'password')
        self.assertEqual(conf.get('PORT'), 1234)

        # Empty
        conf = parse_redis_url(None)
        self.assertEqual(conf.get('HOST'), 'localhost')
        self.assertEqual(conf.get('DB'), 0)
        self.assertEqual(conf.get('PASSWORD'), None)
        self.assertEqual(conf.get('PORT'), 6379)

        # no db
        conf = parse_redis_url("redis://:password@localhost2:1234")
        self.assertEqual(conf.get('HOST'), 'localhost2')
        self.assertEqual(conf.get('DB'), 0)
        self.assertEqual(conf.get('PASSWORD'), 'password')
        self.assertEqual(conf.get('PORT'), 1234)

        # no password
        conf = parse_redis_url("redis://localhost2:1234/0")
        self.assertEqual(conf.get('HOST'), 'localhost2')
        self.assertEqual(conf.get('DB'), 0)
        self.assertEqual(conf.get('PASSWORD'), None)
        self.assertEqual(conf.get('PORT'), 1234)

    def test_get_ip_address_from_request(self):
        req = HttpRequest()
        req.META['REMOTE_ADDR'] = '1.2.3.4'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

        req = HttpRequest()
        req.META['REMOTE_ADDR'] = '1.2.3.4 '
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

        req = HttpRequest()
        req.META['REMOTE_ADDR'] = '192.168.100.34.y'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '127.0.0.1')

        req = HttpRequest()
        req.META['REMOTE_ADDR'] = 'cat'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '127.0.0.1')

        req = HttpRequest()
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '127.0.0.1')

    @patch('defender.config.BEHIND_REVERSE_PROXY', True)
    @patch('defender.config.REVERSE_PROXY_HEADER', 'HTTP_X_PROXIED')
    def test_get_ip_reverse_proxy_custom_header(self):
        req = HttpRequest()
        req.META['HTTP_X_PROXIED'] = '1.2.3.4'
        self.assertEqual(utils.get_ip(req), '1.2.3.4')

        req = HttpRequest()
        req.META['HTTP_X_PROXIED'] = '1.2.3.4, 5.6.7.8, 127.0.0.1'
        self.assertEqual(utils.get_ip(req), '1.2.3.4')

        req = HttpRequest()
        req.META['REMOTE_ADDR'] = '1.2.3.4'
        self.assertEqual(utils.get_ip(req), '1.2.3.4')

    @patch('defender.config.BEHIND_REVERSE_PROXY', True)
    @patch('defender.config.REVERSE_PROXY_HEADER', 'HTTP_X_REAL_IP')
    def test_get_user_attempts(self):
        ip_attempts = random.randint(3, 12)
        username_attempts = random.randint(3, 12)
        for i in range(0, ip_attempts):
            utils.increment_key(utils.get_ip_attempt_cache_key('1.2.3.4'))
        for i in range(0, username_attempts):
            utils.increment_key(utils.get_username_attempt_cache_key('foobar'))
        req = HttpRequest()
        req.POST['username'] = 'foobar'
        req.META['HTTP_X_REAL_IP'] = '1.2.3.4'
        self.assertEqual(
            utils.get_user_attempts(req), max(ip_attempts, username_attempts)
        )

        req = HttpRequest()
        req.POST['username'] = 'foobar'
        req.META['HTTP_X_REAL_IP'] = '5.6.7.8'
        self.assertEqual(
            utils.get_user_attempts(req), username_attempts
        )

        req = HttpRequest()
        req.POST['username'] = 'barfoo'
        req.META['HTTP_X_REAL_IP'] = '1.2.3.4'
        self.assertEqual(
            utils.get_user_attempts(req), ip_attempts
        )

    def test_admin(self):
        """ test the admin pages for this app """
        from .admin import AccessAttemptAdmin
        AccessAttemptAdmin

    def test_decorator_middleware(self):
        # because watch_login is called twice in this test (once by the
        # middleware and once by the decorator) we have half as many attempts
        # before getting locked out.
        # this is getting called twice, once for each decorator, not sure how
        # to dynamically remove one of the middlewares during a test so we
        # divide the failure limit by 2.

        for i in range(0, int(config.FAILURE_LIMIT)):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_get_view(self):
        """ Check that the decorator doesn't tamper with GET requests"""
        for i in range(0, config.FAILURE_LIMIT):
            response = self.client.get(ADMIN_LOGIN_URL)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertNotContains(response, self.LOCKED_MESSAGE)

    @patch('defender.config.USE_CELERY', True)
    def test_use_celery(self):
        """ Check that use celery works"""

        self.assertEqual(AccessAttempt.objects.count(), 0)

        for i in range(0, int(config.FAILURE_LIMIT)):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

        self.assertEqual(AccessAttempt.objects.count(),
                          config.FAILURE_LIMIT + 1)
        self.assertIsNotNone(str(AccessAttempt.objects.all()[0]))

    @patch('defender.config.LOCKOUT_BY_IP_USERNAME', True)
    def test_lockout_by_ip_and_username(self):
        """Check that lockout still works when locking out by IP and Username combined"""

        username = 'testy'

        for i in range(0, config.FAILURE_LIMIT):
            response = self._login(username=username)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(username=username)
        self.assertContains(response, self.LOCKED_MESSAGE)

        # We shouldn't get a lockout message when attempting to use no username
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, LOGIN_FORM_KEY)

        # We shouldn't get a lockout message when attempting to use a different username
        response = self._login()
        self.assertContains(response, LOGIN_FORM_KEY)

        # We shouldn't get a lockout message when attempting to use a different ip address
        ip = '74.125.239.60'
        response = self._login(username=VALID_USERNAME, remote_addr=ip)
        # Check if we are in the same login page
        self.assertContains(response, LOGIN_FORM_KEY)

    @patch('defender.config.DISABLE_IP_LOCKOUT', True)
    def test_disable_ip_lockout(self):
        """Check that lockout still works when we disable IP Lock out"""

        username = 'testy'

        # try logging in with the same IP, but different username
        # we shouldn't be blocked.
        # same IP different, usernames
        ip = '74.125.239.60'
        for i in range(0, config.FAILURE_LIMIT + 10):
            login_username = u"{0}{1}".format(username, i)
            response = self._login(username=login_username, remote_addr=ip)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # same username with same IP
        for i in range(0, config.FAILURE_LIMIT):
            response = self._login(username=username)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # But we should get one now
        # same username and Ip, over the limit for username.
        response = self._login(username=username)
        self.assertContains(response, self.LOCKED_MESSAGE)

        # We shouldn't get a lockout message when attempting to use no username
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, LOGIN_FORM_KEY)

        # We shouldn't get a lockout message when attempting to use a different username
        response = self._login()
        self.assertContains(response, LOGIN_FORM_KEY)

        # We shouldn't get a lockout message when attempting to use a different ip address
        second_ip = '74.125.239.99'
        response = self._login(username=VALID_USERNAME, remote_addr=second_ip)
        # Check if we are in the same login page
        self.assertContains(response, LOGIN_FORM_KEY)

        # we should have no ip's blocked
        data_out = utils.get_blocked_ips()
        self.assertEqual(data_out, [])

        # even if we try to manually block one it still won't be in there.
        utils.block_ip(second_ip)

        # we should still have no ip's blocked
        data_out = utils.get_blocked_ips()
        self.assertEqual(data_out, [])


class DefenderTestCaseTest(DefenderTestCase):
    """Make sure that we're cleaning the cache between tests"""
    key = 'test_key'

    def test_first_incr(self):
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)

    def test_second_incr(self):
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)


class DefenderTransactionTestCaseTest(DefenderTransactionTestCase):
    """Make sure that we're cleaning the cache between tests"""
    key = 'test_key'

    def test_first_incr(self):
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)

    def test_second_incr(self):
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)


class TestUtils(DefenderTestCase):
    def test_username_blocking(self):
        username = 'foo'
        self.assertFalse(utils.is_user_already_locked(username))
        utils.block_username(username)
        self.assertTrue(utils.is_user_already_locked(username))
        utils.unblock_username(username)
        self.assertFalse(utils.is_user_already_locked(username))

    def test_ip_address_blocking(self):
        ip = '1.2.3.4'
        self.assertFalse(utils.is_source_ip_already_locked(ip))
        utils.block_ip(ip)
        self.assertTrue(utils.is_source_ip_already_locked(ip))
        utils.unblock_ip(ip)
        self.assertFalse(utils.is_source_ip_already_locked(ip))
