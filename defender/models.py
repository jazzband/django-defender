from django.db import models


class AccessAttempt(models.Model):
    user_agent = models.CharField(
        max_length=255,
    )
    ip_address = models.GenericIPAddressField(
        verbose_name='IP Address',
        null=True,
    )
    username = models.CharField(
        max_length=255,
        null=True,
    )
    http_accept = models.CharField(
        verbose_name='HTTP Accept',
        max_length=1025,
    )
    path_info = models.CharField(
        verbose_name='Path',
        max_length=255,
    )
    attempt_time = models.DateTimeField(
        auto_now_add=True,
    )
    login_valid = models.BooleanField(
        default=False,
    )

    class Meta:
        ordering = ['-attempt_time']
