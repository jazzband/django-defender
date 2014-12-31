import random
import string
import time

from mock import patch
import mockredis

from django.test import TestCase
from django.contrib.auth.models import User
from django.core.urlresolvers import NoReverseMatch
from django.core.urlresolvers import reverse

from .utils import (
    COOLOFF_TIME, FAILURE_LIMIT, reset_failed_attempts)


redis_client = mockredis.mock_strict_redis_client()

# Django >= 1.7 compatibility
try:
    ADMIN_LOGIN_URL = reverse('admin:login')
    LOGIN_FORM_KEY = '<form action="/admin/" method="post" id="login-form">'
except NoReverseMatch:
    ADMIN_LOGIN_URL = reverse('admin:index')
    LOGIN_FORM_KEY = 'this_is_the_login_form'


class AccessAttemptTest(TestCase):
    """Test case using custom settings for testing
    """
    VALID_USERNAME = 'valid'
    LOCKED_MESSAGE = 'Account locked: too many login attempts.'

    def _get_random_str(self):
        """ Returns a random str """
        chars = string.ascii_uppercase + string.digits

        return ''.join(random.choice(chars) for x in range(20))

    @patch('defender.utils.redis_server', redis_client)
    def _login(self, is_valid=False, user_agent='test-browser'):
        """Login a user. A valid credential is used when is_valid is True,
           otherwise it will use a random string to make a failed login.
        """
        username = self.VALID_USERNAME if is_valid else self._get_random_str()

        response = self.client.post(ADMIN_LOGIN_URL, {
            'username': username,
            'password': username,
            LOGIN_FORM_KEY: 1,
        }, HTTP_USER_AGENT=user_agent)

        return response

    @patch('defender.utils.redis_server', redis_client)
    def setUp(self):
        """Create a valid user for login
        """
        self.user = User.objects.create_superuser(
            username=self.VALID_USERNAME,
            email='test@example.com',
            password=self.VALID_USERNAME,
        )

    def tearDown(self):
        """ clean up the db """
        redis_client.flushdb()

    @patch('defender.utils.redis_server', redis_client)
    def test_failure_limit_once(self):
        """Tests the login lock trying to login one more time
        than failure limit
        """
        for i in range(0, FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

    @patch('defender.utils.redis_server', redis_client)
    def test_failure_limit_many(self):
        """Tests the login lock trying to login a lot of times more
        than failure limit
        """
        for i in range(0, FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        for i in range(0, random.randrange(1, 10)):
            # try to log in a bunch of times
            response = self._login()
            self.assertContains(response, self.LOCKED_MESSAGE)

    @patch('defender.utils.redis_server', redis_client)
    def test_valid_login(self):
        """Tests a valid login for a real username
        """
        response = self._login(is_valid=True)
        self.assertNotContains(response, LOGIN_FORM_KEY, status_code=302)

    @patch('defender.utils.redis_server', redis_client)
    def test_cooling_off(self):
        """Tests if the cooling time allows a user to login
        """
        self.test_failure_limit_once()
        # Wait for the cooling off period
        time.sleep(COOLOFF_TIME)
        # mock redis require that we expire on our own
        redis_client.do_expire()
        # It should be possible to login again, make sure it is.
        self.test_valid_login()

    @patch('defender.utils.redis_server', redis_client)
    def test_cooling_off_for_trusted_user(self):
        """Test the cooling time for a trusted user
        """
        # Try the cooling off time
        self.test_cooling_off()

    @patch('defender.utils.redis_server', redis_client)
    def test_long_user_agent_valid(self):
        """Tests if can handle a long user agent
        """
        long_user_agent = 'ie6' * 1024
        response = self._login(is_valid=True, user_agent=long_user_agent)
        self.assertNotContains(response, LOGIN_FORM_KEY, status_code=302)

    @patch('defender.utils.redis_server', redis_client)
    def test_long_user_agent_not_valid(self):
        """Tests if can handle a long user agent with failure
        """
        long_user_agent = 'ie6' * 1024
        for i in range(0, FAILURE_LIMIT + 1):
            response = self._login(user_agent=long_user_agent)

        self.assertContains(response, self.LOCKED_MESSAGE)

    @patch('defender.utils.redis_server', redis_client)
    def test_reset_ip(self):
        """Tests if can reset an ip address
        """
        # Make a lockout
        self.test_failure_limit_once()

        # Reset the ip so we can try again
        reset_failed_attempts(ip='127.0.0.1')

        # Make a login attempt again
        self.test_valid_login()
