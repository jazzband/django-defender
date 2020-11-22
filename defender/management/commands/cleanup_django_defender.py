from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from ...models import AccessAttempt
from ... import config


class Command(BaseCommand):
    """ clean up management command """

    help = "Cleans up django-defender AccessAttempt table"

    def handle(self, **options):
        """
        Removes any entries in the AccessAttempt that are older
        than your DEFENDER_ACCESS_ATTEMPT_EXPIRATION config, default 24 HOURS.
        """
        print("Starting clean up of django-defender table")
        now = timezone.now()
        cleanup_delta = timedelta(hours=config.ACCESS_ATTEMPT_EXPIRATION)
        min_attempt_time = now - cleanup_delta

        attempts_to_clean = AccessAttempt.objects.filter(
            attempt_time__lt=min_attempt_time,
        )
        attempts_to_clean_count = attempts_to_clean.count()

        attempts_to_clean.delete()

        print(
            "Finished. Removed {0} AccessAttempt entries.".format(
                attempts_to_clean_count
            )
        )
