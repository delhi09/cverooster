from django.contrib.auth.models import AbstractUser
from django.db import models


class BaseModel(models.Model):
    created_by = models.CharField(max_length=32, null=False)
    created_at = models.DateTimeField(null=False)
    updated_by = models.CharField(max_length=32, null=False)
    updated_at = models.DateTimeField(null=False)

    class Meta:
        abstract = True


class CveLabel(BaseModel):
    class Meta:
        db_table = "cve_label"

    cve_label_id = models.IntegerField(null=False, primary_key=True)
    cve_label_code = models.CharField(max_length=16, null=False)
    cve_label_name = models.CharField(max_length=16, null=False)
    display_order = models.IntegerField(null=False)


class AppUser(AbstractUser):
    class Meta(AbstractUser.Meta):
        db_table = "app_user"

    cve_labels = models.ManyToManyField(
        CveLabel, related_name="app_user", through="UserFilterSettingCveLabel"
    )


class Cve(BaseModel):
    class Meta:
        db_table = "cve"
        constraints = [
            models.UniqueConstraint(
                fields=["cve_year", "cve_number"], name="cve_year_cve_number_unique"
            )
        ]

    cve_id = models.CharField(max_length=16, null=False, primary_key=True)
    cve_year = models.IntegerField(null=False)
    cve_number = models.IntegerField(null=False)
    cve_url = models.CharField(max_length=128, null=False)
    nvd_url = models.CharField(max_length=128, null=True)
    nvd_content_exists = models.BooleanField(null=False)
    cve_description = models.TextField(null=False)
    cvss3_score = models.FloatField(null=True)
    cvss3 = models.ForeignKey(
        to="cvss3",
        db_column="cvss3_severity",
        to_field="cvss3_severity_code",
        on_delete=models.PROTECT,
        null=True,
        related_name="cvss3",
    )
    cvss3_vector = models.CharField(max_length=64, null=True)
    cvss2_score = models.FloatField(null=True)
    cvss2 = models.ForeignKey(
        to="cvss2",
        db_column="cvss2_severity",
        to_field="cvss2_severity_code",
        on_delete=models.PROTECT,
        null=True,
        related_name="cvss2",
    )
    cvss2_vector = models.CharField(max_length=64, null=True)
    published_date = models.DateTimeField(null=True)
    last_modified_date = models.DateTimeField(null=True)


class CveFullTextSearch(BaseModel):
    class Meta:
        db_table = "cve_full_text_search"

    # DB設計上は不要だが、Djangoで複合主キーを実現できないため、仕方なく宣言する。
    id = models.AutoField(primary_key=True)

    cve = models.OneToOneField(
        Cve,
        unique=True,
        db_index=True,
        on_delete=models.CASCADE,
        related_name="cve_full_text_search",
    )
    cve_text_for_search = models.TextField(null=False)


class Cvss3(BaseModel):
    class Meta:
        db_table = "cvss3"
        constraints = [
            models.UniqueConstraint(
                fields=["cvss3_severity_code"], name="cvss3_severity_code_unique"
            )
        ]

    cvss3_severity_code = models.CharField(max_length=16, null=False, primary_key=True)
    cvss3_severity_level = models.IntegerField(null=False)


class Cvss2(BaseModel):
    class Meta:
        db_table = "cvss2"
        constraints = [
            models.UniqueConstraint(
                fields=["cvss2_severity_code"], name="cvss2_severity_code_unique"
            )
        ]

    cvss2_severity_code = models.CharField(max_length=16, null=False, primary_key=True)
    cvss2_severity_level = models.IntegerField(null=False)


class UserKeyword(BaseModel):
    class Meta:
        db_table = "user_keyword"

    # DB設計上は不要だが、Djangoで複合主キーを実現できないため、仕方なく宣言する。
    id = models.AutoField(primary_key=True)

    user = models.ForeignKey(
        AppUser,
        db_column="user_id",
        to_field="id",
        on_delete=models.CASCADE,
        null=False,
    )
    keyword = models.CharField(max_length=32, null=False)


class CveSeverity(BaseModel):
    class Meta:
        db_table = "cve_severity"

    cve_severity_code = models.CharField(max_length=16, null=False, primary_key=True)
    cve_severity_name = models.CharField(max_length=16, null=False)
    display_order = models.IntegerField(null=False)


class UserCveLabel(BaseModel):
    class Meta:
        db_table = "user_cve_label"

    # DB設計上は不要だが、Djangoで複合主キーを実現できないため、仕方なく宣言する。
    id = models.AutoField(primary_key=True)

    user = models.ForeignKey(
        AppUser,
        db_column="user_id",
        to_field="id",
        on_delete=models.CASCADE,
        null=False,
        related_name="user_cve_label",
    )
    cve = models.ForeignKey(
        Cve,
        db_column="cve_id",
        to_field="cve_id",
        on_delete=models.CASCADE,
        null=False,
        related_name="user_cve_label",
    )
    cve_label = models.ForeignKey(
        CveLabel,
        db_column="cve_label_id",
        to_field="cve_label_id",
        on_delete=models.PROTECT,
        null=False,
        related_name="user_cve_label",
    )


class UserCveComment(BaseModel):
    class Meta:
        db_table = "user_cve_comment"

    # DB設計上は不要だが、Djangoで複合主キーを実現できないため、仕方なく宣言する。
    id = models.AutoField(primary_key=True)

    user = models.ForeignKey(
        AppUser,
        db_column="user_id",
        to_field="id",
        on_delete=models.CASCADE,
        null=False,
        related_name="user_cve_comment",
    )
    cve = models.ForeignKey(
        Cve,
        db_column="cve_id",
        to_field="cve_id",
        on_delete=models.CASCADE,
        null=False,
        related_name="user_cve_comment",
    )
    cve_comment = models.CharField(max_length=255, null=False)


class UserFilterSettingCveLabel(models.Model):
    class Meta:
        db_table = "user_filter_setting_cve_label"

    id = models.AutoField(primary_key=True)

    user = models.ForeignKey(
        AppUser,
        db_column="user_id",
        to_field="id",
        on_delete=models.CASCADE,
        null=False,
        related_name="user_filter_setting_cve_label",
    )
    cve_label = models.ForeignKey(
        CveLabel,
        db_column="cve_label_id",
        to_field="cve_label_id",
        on_delete=models.CASCADE,
        null=False,
        related_name="user_filter_setting_cve_label",
    )


class UserMailAddress(BaseModel):
    class Meta:
        db_table = "user_mail_address"

    user = models.ForeignKey(
        AppUser,
        db_column="user_id",
        to_field="id",
        on_delete=models.CASCADE,
        null=False,
    )
    mail_address = models.CharField(max_length=255, null=False)
    notify_mail = models.BooleanField(null=False)


class UserSlackWebhookUrl(BaseModel):
    class Meta:
        db_table = "user_slack_webhook_url"

    user = models.ForeignKey(
        AppUser,
        db_column="user_id",
        to_field="id",
        on_delete=models.CASCADE,
        null=False,
    )
    slack_webhook_url = models.CharField(max_length=255, null=False)
    notify_slack = models.BooleanField(null=False)


class UserFilterSetting(BaseModel):
    class Meta:
        db_table = "user_filter_setting"

    user = models.ForeignKey(
        AppUser,
        db_column="user_id",
        to_field="id",
        on_delete=models.CASCADE,
        null=False,
    )
    severity = models.ForeignKey(
        CveSeverity,
        db_column="severity",
        to_field="cve_severity_code",
        on_delete=models.CASCADE,
        null=True,
    )
    year = models.IntegerField(null=True)
    enable_user_keyword = models.BooleanField(null=False)
