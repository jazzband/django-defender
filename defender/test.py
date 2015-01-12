from django.test.testcases import TestCase, TransactionTestCase

from .connection import get_redis_connection


class DefenderTestCaseMixin(object):
    """Mixin used to provide a common tearDown method"""

    def tearDown(self):
        """cleanup django-defender cache after each test"""
        super(DefenderTestCaseMixin, self).tearDown()
        get_redis_connection().flushdb()


class DefenderTransactionTestCase(DefenderTestCaseMixin, TransactionTestCase):
    """Helper TransactionTestCase that cleans the cache after each test"""
    pass


class DefenderTestCase(DefenderTestCaseMixin, TestCase):
    """Helper TestCase that cleans the cache after each test"""
    pass
