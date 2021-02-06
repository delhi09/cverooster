# Generated by Django 3.0.7 on 2020-07-03 16:57

from django.conf import settings
import django.contrib.auth.models
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0011_update_proxy_permissions"),
    ]

    operations = [
        migrations.CreateModel(
            name="AppUser",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designates that this user has all permissions without explicitly assigning them.",
                        verbose_name="superuser status",
                    ),
                ),
                (
                    "username",
                    models.CharField(
                        error_messages={
                            "unique": "A user with that username already exists."
                        },
                        help_text="Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.",
                        max_length=150,
                        unique=True,
                        validators=[
                            django.contrib.auth.validators.UnicodeUsernameValidator()
                        ],
                        verbose_name="username",
                    ),
                ),
                (
                    "first_name",
                    models.CharField(
                        blank=True, max_length=30, verbose_name="first name"
                    ),
                ),
                (
                    "last_name",
                    models.CharField(
                        blank=True, max_length=150, verbose_name="last name"
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        blank=True, max_length=254, verbose_name="email address"
                    ),
                ),
                (
                    "is_staff",
                    models.BooleanField(
                        default=False,
                        help_text="Designates whether the user can log into this admin site.",
                        verbose_name="staff status",
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(
                        default=True,
                        help_text="Designates whether this user should be treated as active. Unselect this instead of deleting accounts.",
                        verbose_name="active",
                    ),
                ),
                (
                    "date_joined",
                    models.DateTimeField(
                        default=django.utils.timezone.now, verbose_name="date joined"
                    ),
                ),
            ],
            options={
                "verbose_name": "user",
                "verbose_name_plural": "users",
                "db_table": "app_user",
                "abstract": False,
            },
            managers=[
                ("objects", django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name="Cve",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                (
                    "cve_id",
                    models.CharField(max_length=16, primary_key=True, serialize=False),
                ),
                ("cve_year", models.IntegerField()),
                ("cve_number", models.IntegerField()),
                ("cve_url", models.CharField(max_length=128)),
                ("nvd_url", models.CharField(max_length=128, null=True)),
                ("nvd_content_exists", models.BooleanField()),
                ("cve_description", models.TextField()),
                ("cvss3_score", models.FloatField(null=True)),
                ("cvss3_vector", models.CharField(max_length=64, null=True)),
                ("cvss2_score", models.FloatField(null=True)),
                ("cvss2_vector", models.CharField(max_length=64, null=True)),
                ("published_date", models.DateTimeField(null=True)),
                ("last_modified_date", models.DateTimeField(null=True)),
            ],
            options={
                "db_table": "cve",
            },
        ),
        migrations.CreateModel(
            name="CveFullTextSearch",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("cve_text_for_search", models.TextField()),
            ],
            options={
                "db_table": "cve_full_text_search",
            },
        ),
        migrations.CreateModel(
            name="CveLabel",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                (
                    "cve_label_id",
                    models.IntegerField(primary_key=True, serialize=False),
                ),
                ("cve_label_code", models.CharField(max_length=16)),
                ("cve_label_name", models.CharField(max_length=16)),
                ("display_order", models.IntegerField()),
            ],
            options={
                "db_table": "cve_label",
            },
        ),
        migrations.CreateModel(
            name="CveSeverity",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                (
                    "cve_severity_code",
                    models.CharField(max_length=16, primary_key=True, serialize=False),
                ),
                ("cve_severity_name", models.CharField(max_length=16)),
                ("display_order", models.IntegerField()),
            ],
            options={
                "db_table": "cve_severity",
            },
        ),
        migrations.CreateModel(
            name="Cvss2",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                (
                    "cvss2_severity_code",
                    models.CharField(max_length=16, primary_key=True, serialize=False),
                ),
                ("cvss2_severity_level", models.IntegerField()),
            ],
            options={
                "db_table": "cvss2",
            },
        ),
        migrations.CreateModel(
            name="Cvss3",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                (
                    "cvss3_severity_code",
                    models.CharField(max_length=16, primary_key=True, serialize=False),
                ),
                ("cvss3_severity_level", models.IntegerField()),
            ],
            options={
                "db_table": "cvss3",
            },
        ),
        migrations.CreateModel(
            name="UserSlackWebhookUrl",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                ("slack_webhook_url", models.CharField(max_length=255)),
                ("notify_slack", models.BooleanField()),
                (
                    "user",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "user_slack_webhook_url",
            },
        ),
        migrations.CreateModel(
            name="UserMailAddress",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                ("mail_address", models.CharField(max_length=255)),
                ("notify_mail", models.BooleanField()),
                (
                    "user",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "user_mail_address",
            },
        ),
        migrations.CreateModel(
            name="UserKeyword",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("keyword", models.CharField(max_length=32)),
                (
                    "user",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "user_keyword",
            },
        ),
        migrations.CreateModel(
            name="UserFilterSettingCveLabel",
            fields=[
                ("id", models.AutoField(primary_key=True, serialize=False)),
                (
                    "cve_label",
                    models.ForeignKey(
                        db_column="cve_label_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_filter_setting_cve_label",
                        to="core.CveLabel",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_filter_setting_cve_label",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "user_filter_setting_cve_label",
            },
        ),
        migrations.CreateModel(
            name="UserFilterSetting",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                ("year", models.IntegerField(null=True)),
                ("enable_user_keyword", models.BooleanField()),
                (
                    "severity",
                    models.ForeignKey(
                        db_column="severity",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="core.CveSeverity",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "user_filter_setting",
            },
        ),
        migrations.CreateModel(
            name="UserCveLabel",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                ("id", models.AutoField(primary_key=True, serialize=False)),
                (
                    "cve",
                    models.ForeignKey(
                        db_column="cve_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_cve_label",
                        to="core.Cve",
                    ),
                ),
                (
                    "cve_label",
                    models.ForeignKey(
                        db_column="cve_label_id",
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="user_cve_label",
                        to="core.CveLabel",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_cve_label",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "user_cve_label",
            },
        ),
        migrations.CreateModel(
            name="UserCveComment",
            fields=[
                ("created_by", models.CharField(max_length=32)),
                ("created_at", models.DateTimeField()),
                ("updated_by", models.CharField(max_length=32)),
                ("updated_at", models.DateTimeField()),
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("cve_comment", models.CharField(max_length=255)),
                (
                    "cve",
                    models.ForeignKey(
                        db_column="cve_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_cve_comment",
                        to="core.Cve",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        db_column="user_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_cve_comment",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "user_cve_comment",
            },
        ),
        migrations.AddConstraint(
            model_name="cvss3",
            constraint=models.UniqueConstraint(
                fields=("cvss3_severity_code",), name="cvss3_severity_code_unique"
            ),
        ),
        migrations.AddConstraint(
            model_name="cvss2",
            constraint=models.UniqueConstraint(
                fields=("cvss2_severity_code",), name="cvss2_severity_code_unique"
            ),
        ),
        migrations.AddField(
            model_name="cvefulltextsearch",
            name="cve",
            field=models.OneToOneField(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="cve_full_text_search",
                to="core.Cve",
            ),
        ),
        migrations.AddField(
            model_name="cve",
            name="cvss2",
            field=models.ForeignKey(
                db_column="cvss2_severity",
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="cvss2",
                to="core.Cvss2",
            ),
        ),
        migrations.AddField(
            model_name="cve",
            name="cvss3",
            field=models.ForeignKey(
                db_column="cvss3_severity",
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="cvss3",
                to="core.Cvss3",
            ),
        ),
        migrations.AddField(
            model_name="appuser",
            name="cve_labels",
            field=models.ManyToManyField(
                related_name="app_user",
                through="core.UserFilterSettingCveLabel",
                to="core.CveLabel",
            ),
        ),
        migrations.AddField(
            model_name="appuser",
            name="groups",
            field=models.ManyToManyField(
                blank=True,
                help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                related_name="user_set",
                related_query_name="user",
                to="auth.Group",
                verbose_name="groups",
            ),
        ),
        migrations.AddField(
            model_name="appuser",
            name="user_permissions",
            field=models.ManyToManyField(
                blank=True,
                help_text="Specific permissions for this user.",
                related_name="user_set",
                related_query_name="user",
                to="auth.Permission",
                verbose_name="user permissions",
            ),
        ),
        migrations.AddConstraint(
            model_name="cve",
            constraint=models.UniqueConstraint(
                fields=("cve_year", "cve_number"), name="cve_year_cve_number_unique"
            ),
        ),
    ]
