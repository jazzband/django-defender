import random
import string
import time
from unittest.mock import patch

from datetime import datetime, timedelta

from django.contrib.auth.models import AnonymousUser, User
from django.contrib.sessions.backends.db import SessionStore
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.test.client import RequestFactory
from django.test.testcases import TestCase
from redis.client import Redis
from django.urls import reverse

import redis

from defender.data import get_approx_account_lockouts_from_login_attempts

from . import utils
from . import config
from .signals import (
    ip_block as ip_block_signal,
    ip_unblock as ip_unblock_signal,
    username_block as username_block_signal,
    username_unblock as username_unblock_signal,
)
from .connection import parse_redis_url, get_redis_connection
from .decorators import watch_login
from .models import AccessAttempt
from .test import DefenderTestCase, DefenderTransactionTestCase

LOGIN_FORM_KEY = '<form action="/admin/login/" method="post" id="login-form">'
ADMIN_LOGIN_URL = reverse("admin:login")

VALID_USERNAME = VALID_PASSWORD = "valid"
UPPER_USERNAME = "VALID"


class AccessAttemptTest(DefenderTestCase):
    """ Test case using custom settings for testing
    """

    LOCKED_MESSAGE = "Account locked: too many login attempts."
    PERMANENT_LOCKED_MESSAGE = (
        LOCKED_MESSAGE + "  Contact an admin to unlock your account."
    )

    def _get_random_str(self):
        """ Returns a random str """
        chars = string.ascii_uppercase + string.digits

        return "".join(random.choice(chars) for _ in range(20))

    def _login(
        self,
        username=None,
        password=None,
        user_agent="test-browser",
        remote_addr="127.0.0.1",
    ):
        """ Login a user. If the username or password is not provided
        it will use a random string instead. Use the VALID_USERNAME and
        VALID_PASSWORD to make a valid login.
        """
        if username is None:
            username = self._get_random_str()

        if password is None:
            password = self._get_random_str()

        response = self.client.post(
            ADMIN_LOGIN_URL,
            {"username": username, "password": password, LOGIN_FORM_KEY: 1,},
            HTTP_USER_AGENT=user_agent,
            REMOTE_ADDR=remote_addr,
        )

        return response

    def setUp(self):
        """ Create a valid user for login
        """
        self.user = User.objects.create_superuser(
            username=VALID_USERNAME, email="test@example.com", password=VALID_PASSWORD,
        )

    def test_data_integrity_of_get_blocked_ips(self):
        """ Test whether data retrieved from redis via
        get_blocked_ips() is the same as the data saved
        """
        data_in = ["127.0.0.1", "4.2.2.1"]
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
        data_in = ["foo", "bar"]
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
            ip = "74.125.239.{0}.".format(i)
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

    @patch("defender.config.USERNAME_FAILURE_LIMIT", 3)
    def test_username_failure_limit(self):
        """ Tests that the username failure limit setting is
        respected when trying to login one more time than failure limit
        """
        for i in range(0, config.USERNAME_FAILURE_LIMIT):
            ip = "74.125.239.{0}.".format(i)
            response = self._login(username=VALID_USERNAME, remote_addr=ip)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(username=VALID_USERNAME, remote_addr=ip)
        self.assertContains(response, self.LOCKED_MESSAGE)

        # doing a get should not get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, LOGIN_FORM_KEY)

    @patch("defender.config.IP_FAILURE_LIMIT", 3)
    def test_ip_failure_limit(self):
        """ Tests that the IP failure limit setting is
        respected when trying to login one more time than failure limit
        """
        for i in range(0, config.IP_FAILURE_LIMIT):
            username = "john-doe__%d" % i
            response = self._login(username=username)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login(username=VALID_USERNAME)
        self.assertContains(response, self.LOCKED_MESSAGE)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_valid_login(self):
        """ Tests a valid login for a real username
        """
        response = self._login(username=VALID_USERNAME, password=VALID_PASSWORD)
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
            self._login(username=VALID_USERNAME)

        # try to login with a different user
        response = self._login(username="myuser")
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_blocked_username_cannot_login(self):
        """ Test an user with blocked username cannot login using
        another ip
        """
        for i in range(0, config.FAILURE_LIMIT + 1):
            ip = "74.125.239.{0}.".format(i)
            self._login(username=VALID_USERNAME, remote_addr=ip)

        # try to login with a different ip
        response = self._login(username=VALID_USERNAME, remote_addr="8.8.8.8")
        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_blocked_username_uppercase_saved_lower(self):
        """
        Test that a uppercase username is saved in lowercase
        within the cache.
        """
        for i in range(0, config.FAILURE_LIMIT + 2):
            ip = "74.125.239.{0}.".format(i)
            self._login(username=UPPER_USERNAME, remote_addr=ip)

        self.assertNotIn(UPPER_USERNAME, utils.get_blocked_usernames())
        self.assertIn(UPPER_USERNAME.lower(), utils.get_blocked_usernames())

    def test_empty_username_cannot_be_blocked(self):
        """
        Test that an empty username, or one that is None, cannot be blocked.
        """
        for username in ["", None]:
            for i in range(0, config.FAILURE_LIMIT + 2):
                ip = "74.125.239.{0}.".format(i)
                self._login(username=username, remote_addr=ip)

            self.assertNotIn(username, utils.get_blocked_usernames())

    def test_lowercase(self):
        """
        Test that the lowercase(None) returns None.
        """
        self.assertEqual(utils.lower_username(None), None)

    def test_cooling_off(self):
        """ Tests if the cooling time allows a user to login
        """
        self.test_failure_limit_by_ip_once()
        # Wait for the cooling off period
        time.sleep(config.LOCKOUT_COOLOFF_TIMES[0])

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
        long_user_agent = "ie6" * 1024
        response = self._login(
            username=VALID_USERNAME, password=VALID_PASSWORD, user_agent=long_user_agent
        )
        self.assertNotContains(response, LOGIN_FORM_KEY, status_code=302)

    @patch("defender.config.BEHIND_REVERSE_PROXY", True)
    @patch("defender.config.REVERSE_PROXY_HEADER", "HTTP_X_FORWARDED_FOR")
    def test_get_ip_reverse_proxy(self):
        """ Tests if can handle a long user agent
        """
        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.24.24"
        self.assertEqual(utils.get_ip(request), "192.168.24.24")

        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META["REMOTE_ADDR"] = "24.24.24.24"
        self.assertEqual(utils.get_ip(request), "24.24.24.24")

    def test_get_ip(self):
        """ Tests if can handle a long user agent
        """
        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()

        self.assertEqual(utils.get_ip(request), "127.0.0.1")

    def test_long_user_agent_not_valid(self):
        """ Tests if can handle a long user agent with failure
        """
        long_user_agent = "ie6" * 1024
        for i in range(0, config.FAILURE_LIMIT + 1):
            response = self._login(user_agent=long_user_agent)

        self.assertContains(response, self.LOCKED_MESSAGE)

    def test_reset_ip(self):
        """ Tests if can reset an ip address
        """
        # Make a lockout
        self.test_failure_limit_by_ip_once()

        # Reset the ip so we can try again
        utils.reset_failed_attempts(ip_address="127.0.0.1")

        # Make a login attempt again
        self.test_valid_login()

    @patch("defender.config.LOCKOUT_URL", "http://localhost/othe/login/")
    def test_failed_login_redirect_to_url(self):
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
        self.assertEqual(response["Location"], "http://localhost/othe/login/")

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "http://localhost/othe/login/")

    @patch("defender.config.LOCKOUT_URL", "/o/login/")
    def test_failed_login_redirect_to_url_local(self):
        """ Test to make sure that after lockout we send to the correct
        redirect URL """

        for i in range(0, config.FAILURE_LIMIT):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        lockout_url = "/o/login/"

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now, check redirect make sure it is valid.
        response = self._login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], lockout_url)

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], lockout_url)

    @patch("defender.config.LOCKOUT_TEMPLATE", "defender/lockout.html")
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
        self.assertTemplateUsed(response, "defender/lockout.html")

        # doing a get should also get locked out message
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "defender/lockout.html")

    @patch("defender.config.COOLOFF_TIME", 0)
    @patch("defender.config.LOCKOUT_COOLOFF_TIMES", [0])
    def test_failed_login_no_cooloff(self):
        """ failed login no cooloff """
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
        """ test the login model """

        response = self._login()
        self.assertContains(response, LOGIN_FORM_KEY)
        self.assertEqual(AccessAttempt.objects.count(), 1)
        self.assertIsNotNone(str(AccessAttempt.objects.all()[0]))

    def test_is_valid_ip(self):
        """ Test the is_valid_ip() method """
        self.assertEqual(utils.is_valid_ip("192.168.0.1"), True)
        self.assertEqual(utils.is_valid_ip("130.80.100.24"), True)
        self.assertEqual(utils.is_valid_ip("8.8.8.8"), True)
        self.assertEqual(utils.is_valid_ip("127.0.0.1"), True)
        self.assertEqual(utils.is_valid_ip("fish"), False)
        self.assertEqual(utils.is_valid_ip(None), False)
        self.assertEqual(utils.is_valid_ip(""), False)
        self.assertEqual(utils.is_valid_ip("0x41.0x41.0x41.0x41"), False)
        self.assertEqual(utils.is_valid_ip("192.168.100.34.y"), False)
        self.assertEqual(
            utils.is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), True
        )
        self.assertEqual(utils.is_valid_ip("2001:db8:85a3:0:0:8a2e:370:7334"), True)
        self.assertEqual(utils.is_valid_ip("2001:db8:85a3::8a2e:370:7334"), True)
        self.assertEqual(utils.is_valid_ip("::ffff:192.0.2.128"), True)
        self.assertEqual(utils.is_valid_ip("::ffff:8.8.8.8"), True)

    def test_parse_redis_url(self):
        """ test the parse_redis_url method """
        # full regular
        conf = parse_redis_url("redis://user:password@localhost2:1234/2", False)
        self.assertEqual(conf.get("HOST"), "localhost2")
        self.assertEqual(conf.get("DB"), 2)
        self.assertEqual(conf.get("PASSWORD"), "password")
        self.assertEqual(conf.get("PORT"), 1234)
        self.assertEqual(conf.get("USERNAME"), "user")

        # full non local
        conf = parse_redis_url(
            "redis://user:pass@www.localhost.com:1234/2", False)
        self.assertEqual(conf.get("HOST"), "www.localhost.com")
        self.assertEqual(conf.get("DB"), 2)
        self.assertEqual(conf.get("PASSWORD"), "pass")
        self.assertEqual(conf.get("PORT"), 1234)
        self.assertEqual(conf.get("USERNAME"), "user")

        # no user name
        conf = parse_redis_url("redis://password@localhost2:1234/2", False)
        self.assertEqual(conf.get("HOST"), "localhost2")
        self.assertEqual(conf.get("DB"), 2)
        self.assertEqual(conf.get("PASSWORD"), None)
        self.assertEqual(conf.get("PORT"), 1234)

        # no user name 2 with colon
        conf = parse_redis_url("redis://:password@localhost2:1234/2", False)
        self.assertEqual(conf.get("HOST"), "localhost2")
        self.assertEqual(conf.get("DB"), 2)
        self.assertEqual(conf.get("PASSWORD"), "password")
        self.assertEqual(conf.get("PORT"), 1234)

        # Empty
        conf = parse_redis_url(None, False)
        self.assertEqual(conf.get("HOST"), "localhost")
        self.assertEqual(conf.get("DB"), 0)
        self.assertEqual(conf.get("PASSWORD"), None)
        self.assertEqual(conf.get("PORT"), 6379)

        # no db
        conf = parse_redis_url("redis://:password@localhost2:1234", False)
        self.assertEqual(conf.get("HOST"), "localhost2")
        self.assertEqual(conf.get("DB"), 0)
        self.assertEqual(conf.get("PASSWORD"), "password")
        self.assertEqual(conf.get("PORT"), 1234)

        # no password
        conf = parse_redis_url("redis://localhost2:1234/0", False)
        self.assertEqual(conf.get("HOST"), "localhost2")
        self.assertEqual(conf.get("DB"), 0)
        self.assertEqual(conf.get("PASSWORD"), None)
        self.assertEqual(conf.get("PORT"), 1234)

        # password with special character and set the password_quote = True
        conf = parse_redis_url("redis://:calmkart%23%40%21@localhost:6379/0", True)
        self.assertEqual(conf.get("HOST"), "localhost")
        self.assertEqual(conf.get("DB"), 0)
        self.assertEqual(conf.get("PASSWORD"), "calmkart#@!")
        self.assertEqual(conf.get("PORT"), 6379)

        # password without special character and set the password_quote = True
        conf = parse_redis_url("redis://:password@localhost2:1234", True)
        self.assertEqual(conf.get("HOST"), "localhost2")
        self.assertEqual(conf.get("DB"), 0)
        self.assertEqual(conf.get("PASSWORD"), "password")
        self.assertEqual(conf.get("PORT"), 1234)

    @patch("defender.config.DEFENDER_REDIS_NAME", "default")
    def test_get_redis_connection_django_conf(self):
        """ get the redis connection """
        redis_client = get_redis_connection()
        self.assertIsInstance(redis_client, Redis)

    @patch("defender.config.DEFENDER_REDIS_NAME", "bad-key")
    def test_get_redis_connection_django_conf_wrong_key(self):
        """ see if we get the correct error """
        error_msg = "The cache bad-key was not found on the django " "cache settings."
        self.assertRaisesMessage(KeyError, error_msg, get_redis_connection)

    def test_get_ip_address_from_request(self):
        """ get ip from request, make sure it is correct """
        req = HttpRequest()
        req.META["REMOTE_ADDR"] = "1.2.3.4"
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, "1.2.3.4")

        req = HttpRequest()
        req.META["REMOTE_ADDR"] = "1.2.3.4 "
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, "1.2.3.4")

        req = HttpRequest()
        req.META["REMOTE_ADDR"] = "192.168.100.34.y"
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, "127.0.0.1")

        req = HttpRequest()
        req.META["REMOTE_ADDR"] = "cat"
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, "127.0.0.1")

        req = HttpRequest()
        ip = utils.get_ip_address_from_request(req)
        self.assertEqual(ip, "127.0.0.1")

    @patch("defender.config.BEHIND_REVERSE_PROXY", True)
    @patch("defender.config.REVERSE_PROXY_HEADER", "HTTP_X_PROXIED")
    def test_get_ip_reverse_proxy_custom_header(self):
        """ make sure the ip is correct behind reverse proxy """
        req = HttpRequest()
        req.META["HTTP_X_PROXIED"] = "1.2.3.4"
        self.assertEqual(utils.get_ip(req), "1.2.3.4")

        req = HttpRequest()
        req.META["HTTP_X_PROXIED"] = "1.2.3.4, 5.6.7.8, 127.0.0.1"
        self.assertEqual(utils.get_ip(req), "1.2.3.4")

        req = HttpRequest()
        req.META["REMOTE_ADDR"] = "1.2.3.4"
        self.assertEqual(utils.get_ip(req), "1.2.3.4")

    @patch("defender.config.BEHIND_REVERSE_PROXY", True)
    @patch("defender.config.REVERSE_PROXY_HEADER", "HTTP_X_REAL_IP")
    def test_get_user_attempts(self):
        """ Get the user attempts make sure they are correct """
        ip_attempts = random.randint(3, 12)
        username_attempts = random.randint(3, 12)
        for i in range(0, ip_attempts):
            utils.increment_key(utils.get_ip_attempt_cache_key("1.2.3.4"))
        for i in range(0, username_attempts):
            utils.increment_key(utils.get_username_attempt_cache_key("foobar"))
        req = HttpRequest()
        req.POST["username"] = "foobar"
        req.META["HTTP_X_REAL_IP"] = "1.2.3.4"
        self.assertEqual(
            utils.get_user_attempts(req), max(ip_attempts, username_attempts)
        )

        req = HttpRequest()
        req.POST["username"] = "foobar"
        req.META["HTTP_X_REAL_IP"] = "5.6.7.8"
        self.assertEqual(utils.get_user_attempts(req), username_attempts)

        req = HttpRequest()
        req.POST["username"] = "barfoo"
        req.META["HTTP_X_REAL_IP"] = "1.2.3.4"
        self.assertEqual(utils.get_user_attempts(req), ip_attempts)

    def test_admin(self):
        """ test the admin pages for this app """
        from .admin import AccessAttemptAdmin

        AccessAttemptAdmin

    def test_unblock_view_user_with_plus(self):
        """
        There is an available admin view for unblocking a user
        with a plus sign in the username.

        Regression test for #GH76.
        """
        reverse(
            "defender_unblock_username_view", kwargs={"username": "user+test@test.tld"}
        )

    def test_unblock_view_user_with_special_symbols(self):
        """
        There is an available admin view for unblocking a user
        with a exclamation mark sign in the username.
        """
        reverse(
            "defender_unblock_username_view", kwargs={"username": "user!test@test.tld"}
        )

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
        """ Check that the decorator doesn't tamper with GET requests """
        for i in range(0, config.FAILURE_LIMIT):
            response = self.client.get(ADMIN_LOGIN_URL)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertNotContains(response, self.LOCKED_MESSAGE)

    @patch("defender.config.USE_CELERY", True)
    def test_use_celery(self):
        """ Check that use celery works """

        self.assertEqual(AccessAttempt.objects.count(), 0)

        for i in range(0, int(config.FAILURE_LIMIT)):
            response = self._login()
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # So, we shouldn't have gotten a lock-out yet.
        # But we should get one now
        response = self._login()
        self.assertContains(response, self.LOCKED_MESSAGE)

        self.assertEqual(AccessAttempt.objects.count(), config.FAILURE_LIMIT + 1)
        self.assertIsNotNone(str(AccessAttempt.objects.all()[0]))

    @patch("defender.config.LOCKOUT_BY_IP_USERNAME", True)
    def test_lockout_by_ip_and_username(self):
        """ Check that lockout still works when locking out by
           IP and Username combined """

        username = "testy"

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

        # We shouldn't get a lockout message when attempting to use a
        # different username
        response = self._login()
        self.assertContains(response, LOGIN_FORM_KEY)

        # Successful login should not clear IP lock
        self._login(username=VALID_USERNAME, password=VALID_PASSWORD)

        # We should still be locked out for the locked
        # username using the same IP
        response = self._login(username=username)
        self.assertContains(response, self.LOCKED_MESSAGE)

        # We shouldn't get a lockout message when attempting to use a
        # different ip address
        ip = "74.125.239.60"
        response = self._login(username=VALID_USERNAME, remote_addr=ip)
        # Check if we are in the same login page
        self.assertContains(response, LOGIN_FORM_KEY)

    @patch("defender.config.DISABLE_IP_LOCKOUT", True)
    def test_disable_ip_lockout(self):
        """ Check that lockout still works when we disable IP Lock out """

        username = "testy"

        # try logging in with the same IP, but different username
        # we shouldn't be blocked.
        # same IP different, usernames
        ip = "74.125.239.60"
        for i in range(0, config.FAILURE_LIMIT + 10):
            login_username = "{0}{1}".format(username, i)
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

        # We shouldn't get a lockout message when attempting to use a
        # different username
        response = self._login()
        self.assertContains(response, LOGIN_FORM_KEY)

        # We shouldn't get a lockout message when attempting to use a
        # different ip address
        second_ip = "74.125.239.99"
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

    @patch("defender.config.DISABLE_USERNAME_LOCKOUT", True)
    def test_disable_username_lockout(self):
        """ Check lockouting still works when we disable username lockout """

        username = "testy"

        # try logging in with the same username, but different IPs.
        # we shouldn't be locked.
        for i in range(0, config.FAILURE_LIMIT + 10):
            ip = "74.125.126.{0}".format(i)
            response = self._login(username=username, remote_addr=ip)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # same ip and same username
        ip = "74.125.127.1"
        for i in range(0, config.FAILURE_LIMIT):
            response = self._login(username=username, remote_addr=ip)
            # Check if we are in the same login page
            self.assertContains(response, LOGIN_FORM_KEY)

        # But we should get one now
        # same username and Ip, over the limit.
        response = self._login(username=username, remote_addr=ip)
        self.assertContains(response, self.LOCKED_MESSAGE)

        # We shouldn't get a lockout message when attempting to use no username
        response = self.client.get(ADMIN_LOGIN_URL)
        self.assertContains(response, LOGIN_FORM_KEY)

        # We shouldn't get a lockout message when attempting to use a
        # different ip address to be sure that username is not blocked.
        second_ip = "74.125.127.2"
        response = self._login(username=username, remote_addr=second_ip)
        # Check if we are in the same login page
        self.assertContains(response, LOGIN_FORM_KEY)

        # we should have no usernames are blocked
        data_out = utils.get_blocked_usernames()
        self.assertEqual(data_out, [])

        # even if we try to manually block one it still won't be in there.
        utils.block_username(username)

        # we should still have no ip's blocked
        data_out = utils.get_blocked_usernames()
        self.assertEqual(data_out, [])

    @patch("defender.config.BEHIND_REVERSE_PROXY", True)
    @patch("defender.config.IP_FAILURE_LIMIT", 3)
    def test_login_blocked_for_non_standard_login_views_without_msg(self):
        """
        Check that a view wich returns the expected status code is causing
        the user to be locked out when we do not expect a specific message
        to be returned.
        """

        @watch_login(status_code=401)
        def fake_api_401_login_view_without_msg(request):
            """ Fake the api login with 401 """
            return HttpResponse(status=401)

        request_factory = RequestFactory()
        request = request_factory.post("api/login")
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.24.24"

        for _ in range(3):
            fake_api_401_login_view_without_msg(request)

            data_out = utils.get_blocked_ips()
            self.assertEqual(data_out, [])

        fake_api_401_login_view_without_msg(request)

        data_out = utils.get_blocked_ips()
        self.assertEqual(data_out, ["192.168.24.24"])

    @patch("defender.config.BEHIND_REVERSE_PROXY", True)
    @patch("defender.config.IP_FAILURE_LIMIT", 3)
    def test_login_blocked_for_non_standard_login_views_with_msg(self):
        """
        Check that a view wich returns the expected status code and the
        expected message is causing the IP to be locked out.
        """

        @watch_login(status_code=401, msg="Invalid credentials")
        def fake_api_401_login_view_without_msg(request):
            """ Fake the api login with 401 """
            return HttpResponse("Sorry, Invalid credentials", status=401)

        request_factory = RequestFactory()
        request = request_factory.post("api/login")
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.24.24"

        for _ in range(3):
            fake_api_401_login_view_without_msg(request)

            data_out = utils.get_blocked_ips()
            self.assertEqual(data_out, [])

        fake_api_401_login_view_without_msg(request)

        data_out = utils.get_blocked_ips()
        self.assertEqual(data_out, ["192.168.24.24"])

    @patch("defender.config.BEHIND_REVERSE_PROXY", True)
    @patch("defender.config.IP_FAILURE_LIMIT", 3)
    def test_login_non_blocked_for_non_standard_login_views_different_msg(self):
        """
        Check that a view wich returns the expected status code but not the
        expected message is not causing the IP to be locked out.
        """

        @watch_login(status_code=401, msg="Invalid credentials")
        def fake_api_401_login_view_without_msg(request):
            """ Fake the api login with 401 """
            return HttpResponse("Ups, wrong credentials", status=401)

        request_factory = RequestFactory()
        request = request_factory.post("api/login")
        request.user = AnonymousUser()
        request.session = SessionStore()

        request.META["HTTP_X_FORWARDED_FOR"] = "192.168.24.24"

        for _ in range(4):
            fake_api_401_login_view_without_msg(request)

            data_out = utils.get_blocked_ips()
            self.assertEqual(data_out, [])

    @patch("defender.config.ATTEMPT_COOLOFF_TIME", "a")
    def test_bad_attempt_cooloff_configuration(self):
        self.assertRaises(Exception)

    @patch("defender.config.ATTEMPT_COOLOFF_TIME", ["a"])
    def test_bad_attempt_cooloff_configuration_with_list(self):
        self.assertRaises(Exception)

    @patch("defender.config.LOCKOUT_COOLOFF_TIMES", "a")
    def test_bad_lockout_cooloff_configuration(self):
        self.assertRaises(Exception)

    @patch("defender.config.LOCKOUT_COOLOFF_TIMES", [300, "a"])
    def test_bad_list_lockout_cooloff_configuration(self):
        self.assertRaises(Exception)

    @patch("defender.config.LOCKOUT_COOLOFF_TIMES", [300, dict(a="a")])
    def test_bad_list_with_dict_lockout_cooloff_configuration(self):
        self.assertRaises(Exception)

    @patch("defender.config.LOCKOUT_COOLOFF_TIMES", [3, 6])
    @patch("defender.config.IP_FAILURE_LIMIT", 3)
    def test_lockout_cooloff_correctly_scales_with_ip_when_set(self):
        self.test_ip_failure_limit()
        self.assertEqual(utils.get_lockout_cooloff_time(ip_address="127.0.0.1"), 3)
        utils.reset_failed_attempts(ip_address="127.0.0.1")
        self.test_ip_failure_limit()
        self.assertEqual(utils.get_lockout_cooloff_time(ip_address="127.0.0.1"), 6)
        time.sleep(config.LOCKOUT_COOLOFF_TIMES[1])
        if config.MOCK_REDIS:
            # mock redis require that we expire on our own
            get_redis_connection().do_expire()  # pragma: no cover
        self.test_valid_login()

    @patch("defender.config.LOCKOUT_COOLOFF_TIMES", [3, 6])
    @patch("defender.config.USERNAME_FAILURE_LIMIT", 3)
    def test_lockout_cooloff_correctly_scales_with_username_when_set(self):
        self.test_username_failure_limit()
        self.assertEqual(utils.get_lockout_cooloff_time(username=VALID_USERNAME), 3)
        utils.reset_failed_attempts(username=VALID_USERNAME)
        self.test_username_failure_limit()
        self.assertEqual(utils.get_lockout_cooloff_time(username=VALID_USERNAME), 6)
        time.sleep(config.LOCKOUT_COOLOFF_TIMES[1])
        if config.MOCK_REDIS:
            # mock redis require that we expire on our own
            get_redis_connection().do_expire()  # pragma: no cover
        self.test_valid_login()

    @patch("defender.config.STORE_ACCESS_ATTEMPTS", False)
    def test_approx_account_lockout_count_default_case_no_store(self):
        self.assertEqual(get_approx_account_lockouts_from_login_attempts(ip_address="127.0.0.1"), 0)

    def test_approx_account_lockout_count_default_case_empty_args(self):
        self.assertEqual(get_approx_account_lockouts_from_login_attempts(), 0)

    @patch("defender.config.DISABLE_IP_LOCKOUT", True)
    def test_approx_account_lockout_count_default_case_invalid_args_pt1(self):
        with self.assertRaises(Exception):
            get_approx_account_lockouts_from_login_attempts(ip_address="127.0.0.1")

    @patch("defender.config.DISABLE_USERNAME_LOCKOUT", True)
    def test_approx_account_lockout_count_default_case_invalid_args_pt2(self):
        with self.assertRaises(Exception):
            get_approx_account_lockouts_from_login_attempts(username=VALID_USERNAME)


class SignalTest(DefenderTestCase):
    """ Test that signals are properly sent when blocking usernames and IPs.
    """

    def test_should_send_signal_when_blocking_ip(self):
        self.blocked_ip = None

        def handler(sender, ip_address, **kwargs):
            self.blocked_ip = ip_address

        ip_block_signal.connect(handler)
        utils.block_ip("8.8.8.8")
        self.assertEqual(self.blocked_ip, "8.8.8.8")

    def test_should_send_signal_when_unblocking_ip(self):
        self.blocked_ip = "8.8.8.8"

        def handler(sender, ip_address, **kwargs):
            self.blocked_ip = None

        ip_unblock_signal.connect(handler)
        utils.unblock_ip("8.8.8.8")
        self.assertIsNone(self.blocked_ip)

    def test_should_not_send_signal_when_ip_already_blocked(self):
        self.blocked_ip = None

        def handler(sender, ip_address, **kwargs):
            self.blocked_ip = ip_address

        ip_block_signal.connect(handler)

        key = utils.get_ip_blocked_cache_key("8.8.8.8")
        utils.REDIS_SERVER.set(key, "blocked")

        utils.block_ip("8.8.8.8")
        self.assertIsNone(self.blocked_ip)

    def test_should_send_signal_when_blocking_username(self):
        self.blocked_username = None

        def handler(sender, username, **kwargs):
            self.blocked_username = username

        username_block_signal.connect(handler)
        utils.block_username("richard_hendricks")
        self.assertEqual(self.blocked_username, "richard_hendricks")

    def test_should_send_signal_when_unblocking_username(self):
        self.blocked_username = "richard_hendricks"

        def handler(sender, username, **kwargs):
            self.blocked_username = None

        username_unblock_signal.connect(handler)
        utils.unblock_username("richard_hendricks")
        self.assertIsNone(self.blocked_username)

    def test_should_not_send_signal_when_username_already_blocked(self):
        self.blocked_username = None

        def handler(sender, username, **kwargs):
            self.blocked_username = username

        username_block_signal.connect(handler)

        key = utils.get_username_blocked_cache_key("richard hendricks")
        utils.REDIS_SERVER.set(key, "blocked")

        utils.block_ip("richard hendricks")
        self.assertIsNone(self.blocked_username)


class DefenderTestCaseTest(DefenderTestCase):
    """ Make sure that we're cleaning the cache between tests """

    key = "test_key"

    def test_first_incr(self):
        """ first increment """
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)

    def test_second_incr(self):
        """ second increment """
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)


class DefenderTransactionTestCaseTest(DefenderTransactionTestCase):
    """ Make sure that we're cleaning the cache between tests """

    key = "test_key"

    def test_first_incr(self):
        """ first increment """
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)

    def test_second_incr(self):
        """ second increment """
        utils.REDIS_SERVER.incr(self.key)
        result = int(utils.REDIS_SERVER.get(self.key))
        self.assertEqual(result, 1)


class TestUtils(DefenderTestCase):
    """ Unit tests for util methods """

    def test_username_blocking(self):
        """ test username blocking """
        username = "foo"
        self.assertFalse(utils.is_user_already_locked(username))
        utils.block_username(username)
        self.assertTrue(utils.is_user_already_locked(username))
        utils.unblock_username(username)
        self.assertFalse(utils.is_user_already_locked(username))

    def test_ip_address_blocking(self):
        """ ip address blocking """
        ip = "1.2.3.4"
        self.assertFalse(utils.is_source_ip_already_locked(ip))
        utils.block_ip(ip)
        self.assertTrue(utils.is_source_ip_already_locked(ip))
        utils.unblock_ip(ip)
        self.assertFalse(utils.is_source_ip_already_locked(ip))

    def test_username_argument_precedence(self):
        """ test that the optional username argument has highest precedence
        when provided """
        request_factory = RequestFactory()
        request = request_factory.get(ADMIN_LOGIN_URL)
        request.user = AnonymousUser()
        request.session = SessionStore()
        username = "johndoe"

        utils.block_username(request.user.username)

        self.assertFalse(utils.is_already_locked(request, username=username))

        utils.check_request(request, True, username=username)
        self.assertEqual(utils.get_user_attempts(request, username=username), 1)

        utils.add_login_attempt_to_db(request, True, username=username)
        self.assertEqual(AccessAttempt.objects.filter(username=username).count(), 1)

    def test_ip_address_strip_port_number(self):
        """ Test the strip_port_number() method """
        # IPv4 with/without port
        self.assertEqual(utils.strip_port_number("192.168.1.1"), "192.168.1.1")
        self.assertEqual(utils.strip_port_number(
            "192.168.1.1:8000"), "192.168.1.1")

        # IPv6 with/without port
        self.assertEqual(utils.strip_port_number(
            "2001:db8:85a3:0:0:8a2e:370:7334"), "2001:db8:85a3:0:0:8a2e:370:7334")
        self.assertEqual(utils.strip_port_number(
            "[2001:db8:85a3:0:0:8a2e:370:7334]:123456"), "2001:db8:85a3:0:0:8a2e:370:7334")

    @patch("defender.config.BEHIND_REVERSE_PROXY", True)
    def test_get_ip_strips_port_number(self):
        """ make sure the IP address is stripped of its port number """
        req = HttpRequest()
        req.META["HTTP_X_FORWARDED_FOR"] = "1.2.3.4:123456"
        self.assertEqual(utils.get_ip(req), "1.2.3.4")

        req = HttpRequest()
        req.META["HTTP_X_FORWARDED_FOR"] = "[2001:db8::1]:123456"
        self.assertEqual(utils.get_ip(req), "2001:db8::1")

    def test_remove_prefix(self):
        """ test the remove_prefix() method """
        self.assertEqual(utils.remove_prefix(
            "defender:blocked:ip:192.168.24.24", "defender:blocked:"), "ip:192.168.24.24")
        self.assertEqual(utils.remove_prefix(
            "defender:blocked:username:johndoe", "defender:blocked:"), "username:johndoe")
        self.assertEqual(utils.remove_prefix(
            "defender:blocked:username:johndoe", "blocked:username:"),
            "defender:blocked:username:johndoe")


class TestRedisConnection(TestCase):
    """ Test the redis connection parsing """
    REDIS_URL_PLAIN = "redis://localhost:6379/0"
    REDIS_URL_PASS = "redis://:mypass@localhost:6379/0"
    REDIS_URL_NAME_PASS = "redis://myname:mypass2@localhost:6379/0"

    @patch("defender.config.DEFENDER_REDIS_URL", REDIS_URL_PLAIN)
    @patch("defender.config.MOCK_REDIS", False)
    def test_get_redis_connection(self):
        """ get redis connection plain """
        redis_client = get_redis_connection()
        self.assertIsInstance(redis_client, Redis)
        redis_client.set('test', 0)
        result = int(redis_client.get('test'))
        self.assertEqual(result, 0)
        redis_client.delete('test')

    @patch("defender.config.DEFENDER_REDIS_URL", REDIS_URL_PASS)
    @patch("defender.config.MOCK_REDIS", False)
    def test_get_redis_connection_with_password(self):
        """ get redis connection with password """

        connection = redis.Redis()
        connection.config_set('requirepass', 'mypass')

        redis_client = get_redis_connection()
        self.assertIsInstance(redis_client, Redis)
        redis_client.set('test2', 0)
        result = int(redis_client.get('test2'))
        self.assertEqual(result, 0)
        redis_client.delete('test2')
        # clean up
        redis_client.config_set('requirepass', '')

    @patch("defender.config.DEFENDER_REDIS_URL", REDIS_URL_NAME_PASS)
    @patch("defender.config.MOCK_REDIS", False)
    def test_get_redis_connection_with_acl(self):
        """ get redis connection with password and name ACL """
        connection = redis.Redis()

        if connection.info().get('redis_version') < '6':
            # redis versions before 6 don't have acl, so skip.
            return

        connection.acl_setuser(
            'myname',
            enabled=True,
            passwords=["+" + "mypass2", ],
            keys="*",
            commands=["+@all", ])

        try:
            redis_client = get_redis_connection()
            self.assertIsInstance(redis_client, Redis)
            redis_client.set('test3', 0)
            result = int(redis_client.get('test3'))
            self.assertEqual(result, 0)
            redis_client.delete('test3')
        except Exception as e:
            raise e

        # clean up
        connection.acl_deluser('myname')
