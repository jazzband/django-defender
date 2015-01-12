import random
import string
import time

from mock import patch

from django.test import TestCase
from django.test.client import RequestFactory
from django.contrib.auth.models import User
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.db import SessionStore
from django.core.urlresolvers import NoReverseMatch
from django.core.urlresolvers import reverse
from django.http import HttpRequest

from .connection import parse_redis_url, get_redis_connection
from . import utils
from . import config
from .models import AccessAttempt


# Django >= 1.7 compatibility
try:
    LOGIN_FORM_KEY = '<form action="/admin/login/" method="post" id="login-form">'
    ADMIN_LOGIN_URL = reverse('admin:login')
except NoReverseMatch:
    ADMIN_LOGIN_URL = reverse('admin:index')
    LOGIN_FORM_KEY = 'this_is_the_login_form'


VALID_USERNAME = VALID_PASSWORD = 'valid'


class AccessAttemptTest(TestCase):
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

    def tearDown(self):
        """ clean up the db """
        get_redis_connection().flushdb()

    def test_login_get(self):
        """ visit the login page """
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEquals(response.status_code, 200)

    def test_failure_limit_once(self):
        """ Tests the login lock trying to login one more time
        than failure limit
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

    def test_failure_limit_many(self):
        """ Tests the login lock trying to login a lot of times more
        than failure limit
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

    def test_valid_login(self):
        """ Tests a valid login for a real username
        """
        response = self._login(username=VALID_USERNAME, password=VALID_PASSWORD)
        self.assertNotContains(response, LOGIN_FORM_KEY, status_code=302)

    def test_blocked_ip_cannot_login(self):
        """ Test an user with blocked ip cannot login with another username
        """
        for i in range(0, config.FAILURE_LIMIT + 1):
            response = self._login(username=VALID_USERNAME)

        # try to login with a different user
        response = self._login(username='myuser')
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_trusted_user_can_login(self):
        """ Test an user with a non-blocked ip can login after an attacker has
        triggered a block with a different ip.
        """
        for i in range(0, config.FAILURE_LIMIT + 1):
            response = self._login(username=VALID_USERNAME)

        # change the client ip so that can we login again
        response = self._login(username=VALID_USERNAME, password=VALID_PASSWORD,
                               remote_addr='8.8.8.8')
        self.assertNotContains(response, LOGIN_FORM_KEY, status_code=302)

    def test_cooling_off(self):
        """ Tests if the cooling time allows a user to login
        """
        self.test_failure_limit_once()
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
    def test_get_ip_reverse_proxy(self):
        """ Tests if can handle a long user agent
        """
        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META['HTTP_X_FORWARDED_FOR'] = '192.168.24.24'
        self.assertEquals(utils.get_ip(request), '192.168.24.24')

        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META['REMOTE_ADDR'] = '24.24.24.24'
        self.assertEquals(utils.get_ip(request), '24.24.24.24')

    def test_get_ip(self):
        """ Tests if can handle a long user agent
        """
        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        self.assertEquals(utils.get_ip(request), '127.0.0.1')

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
        self.test_failure_limit_once()

        # Reset the ip so we can try again
        utils.reset_failed_attempts(ip='127.0.0.1')

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
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response['Location'], 'http://localhost/othe/login/')

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response['Location'], 'http://localhost/othe/login/')

    @patch('defender.config.LOCKOUT_URL', '/o/login/')
    def test_failed_login_redirect_to_URL_local(self):
        """ Test to make sure that after lockout we send to the correct
        redirect URL """

        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now, check redirect make sure it is valid.
        response = self._login()
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response['Location'], 'http://testserver/o/login/')

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEquals(response.status_code, 302)
        self.assertEquals(response['Location'], 'http://testserver/o/login/')

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
        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'defender/lockout.html')

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEquals(response.status_code, 200)
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
        self.assertEquals(AccessAttempt.objects.count(), 1)
        self.assertIsNotNone(str(AccessAttempt.objects.all()[0]))

    def test_is_valid_ip(self):
        """ Test the is_valid_ip() method
        """
        self.assertEquals(utils.is_valid_ip('192.168.0.1'), True)
        self.assertEquals(utils.is_valid_ip('130.80.100.24'), True)
        self.assertEquals(utils.is_valid_ip('8.8.8.8'), True)
        self.assertEquals(utils.is_valid_ip('127.0.0.1'), True)
        self.assertEquals(utils.is_valid_ip('fish'), False)
        self.assertEquals(utils.is_valid_ip(None), False)
        self.assertEquals(utils.is_valid_ip(''), False)

    def test_parse_redis_url(self):
        """ test the parse_redis_url method """
        # full regular
        conf = parse_redis_url("redis://user:password@localhost2:1234/2")
        self.assertEquals(conf.get('HOST'), 'localhost2')
        self.assertEquals(conf.get('DB'), 2)
        self.assertEquals(conf.get('PASSWORD'), 'password')
        self.assertEquals(conf.get('PORT'), 1234)

        # full non local
        conf = parse_redis_url("redis://user:pass@www.localhost.com:1234/2")
        self.assertEquals(conf.get('HOST'), 'www.localhost.com')
        self.assertEquals(conf.get('DB'), 2)
        self.assertEquals(conf.get('PASSWORD'), 'pass')
        self.assertEquals(conf.get('PORT'), 1234)

        # no user name
        conf = parse_redis_url("redis://password@localhost2:1234/2")
        self.assertEquals(conf.get('HOST'), 'localhost2')
        self.assertEquals(conf.get('DB'), 2)
        self.assertEquals(conf.get('PASSWORD'), None)
        self.assertEquals(conf.get('PORT'), 1234)

        # no user name 2 with colon
        conf = parse_redis_url("redis://:password@localhost2:1234/2")
        self.assertEquals(conf.get('HOST'), 'localhost2')
        self.assertEquals(conf.get('DB'), 2)
        self.assertEquals(conf.get('PASSWORD'), 'password')
        self.assertEquals(conf.get('PORT'), 1234)

        # Empty
        conf = parse_redis_url(None)
        self.assertEquals(conf.get('HOST'), 'localhost')
        self.assertEquals(conf.get('DB'), 0)
        self.assertEquals(conf.get('PASSWORD'), None)
        self.assertEquals(conf.get('PORT'), 6379)

        # no db
        conf = parse_redis_url("redis://:password@localhost2:1234")
        self.assertEquals(conf.get('HOST'), 'localhost2')
        self.assertEquals(conf.get('DB'), 0)
        self.assertEquals(conf.get('PASSWORD'), 'password')
        self.assertEquals(conf.get('PORT'), 1234)

        # no password
        conf = parse_redis_url("redis://localhost2:1234/0")
        self.assertEquals(conf.get('HOST'), 'localhost2')
        self.assertEquals(conf.get('DB'), 0)
        self.assertEquals(conf.get('PASSWORD'), None)
        self.assertEquals(conf.get('PORT'), 1234)

    def test_get_ip_address_from_request(self):
        req = HttpRequest()
        req.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

        req = HttpRequest()
        req.META['HTTP_X_FORWARDED_FOR'] = ','.join(
            ['192.168.100.23', '1.2.3.4']
        )
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

        req = HttpRequest()
        req.META['HTTP_X_FORWARDED_FOR'] = '192.168.100.34'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '127.0.0.1')

        req = HttpRequest()
        req.META['HTTP_X_FORWARDED_FOR'] = '127.0.0.1'
        req.META['HTTP_X_REAL_IP'] = '1.2.3.4'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

        req = HttpRequest()
        req.META['HTTP_X_FORWARDED_FOR'] = '1.2.3.4'
        req.META['HTTP_X_REAL_IP'] = '5.6.7.8'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

        req = HttpRequest()
        req.META['HTTP_X_REAL_IP'] = '5.6.7.8'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '5.6.7.8')

        req = HttpRequest()
        req.META['REMOTE_ADDR'] = '1.2.3.4'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

        req = HttpRequest()
        req.META['HTTP_X_FORWARDED_FOR'] = ','.join(
            ['127.0.0.1', '192.168.132.98']
        )
        req.META['HTTP_X_REAL_IP'] = '10.0.0.34'
        req.META['REMOTE_ADDR'] = '1.2.3.4'
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, '1.2.3.4')

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

    @patch('defender.config.PROTECTED_LOGINS', (ADMIN_LOGIN_URL, ))
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

        self.assertEquals(AccessAttempt.objects.count(), 0)

        for i in range(0, int(config.FAILURE_LIMIT)):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

        self.assertEquals(AccessAttempt.objects.count(),
                          config.FAILURE_LIMIT+1)
        self.assertIsNotNone(str(AccessAttempt.objects.all()[0]))
