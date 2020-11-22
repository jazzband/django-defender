from django.db import models, migrations


class Migration(migrations.Migration):
    """ Initial migrations """

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AccessAttempt",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                ("user_agent", models.CharField(max_length=255)),
                (
                    "ip_address",
                    models.GenericIPAddressField(null=True, verbose_name="IP Address"),
                ),
                ("username", models.CharField(max_length=255, null=True)),
                (
                    "http_accept",
                    models.CharField(max_length=1025, verbose_name="HTTP Accept"),
                ),
                ("path_info", models.CharField(max_length=255, verbose_name="Path")),
                ("attempt_time", models.DateTimeField(auto_now_add=True)),
                ("login_valid", models.BooleanField(default=False)),
            ],
            options={"ordering": ["-attempt_time"],},
            bases=(models.Model,),
        ),
    ]
