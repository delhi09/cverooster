from datetime import datetime

import factory
from django.utils import timezone

from core.models import (
    AppUser,
    Cve,
    CveFullTextSearch,
    CveLabel,
    Cvss2,
    Cvss3,
    UserCveComment,
    UserCveLabel,
    UserKeyword,
)

DEFAULT_STRING = "dummy"

DEFAULT_DT = timezone.make_aware(
    datetime(year=2020, month=1, day=1, hour=0, minute=0, second=0)
)


class Cvss3Factory(factory.django.DjangoModelFactory):
    class Meta:
        model = Cvss3
        django_get_or_create = ("cvss3_severity_code",)

    cvss3_severity_code = "LOW"
    cvss3_severity_level = 2
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT


class Cvss2Factory(factory.django.DjangoModelFactory):
    class Meta:
        model = Cvss2
        django_get_or_create = ("cvss2_severity_code",)

    cvss2_severity_code = "LOW"
    cvss2_severity_level = 1
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT


class CveFullTextSearchFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CveFullTextSearch
        django_get_or_create = ("cve",)

    id = None
    cve = factory.SubFactory("api.tests.factories.CveFactory", cve=None)
    cve_text_for_search = DEFAULT_STRING
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT


class CveFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Cve
        django_get_or_create = ("cve_id",)

    cve_id = "CVE-2019-0001"
    cve_year = 2019
    cve_number = 1
    cve_url = DEFAULT_STRING
    nvd_url = DEFAULT_STRING
    nvd_content_exists = True
    cve_description = DEFAULT_STRING
    cvss3_score = 1.0
    cvss3 = factory.SubFactory(Cvss3Factory)
    cvss3_vector = DEFAULT_STRING
    cvss2_score = 1.0
    cvss2 = factory.SubFactory(Cvss2Factory)
    cvss2_vector = DEFAULT_STRING
    published_date = DEFAULT_DT
    last_modified_date = DEFAULT_DT
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT
    cve_full_text_search = factory.RelatedFactory(CveFullTextSearchFactory, "cve")


class UserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = AppUser
        django_get_or_create = ("username",)

    id = None
    password = factory.PostGenerationMethodCall("set_password", DEFAULT_STRING)
    last_login = None
    is_superuser = False
    username = DEFAULT_STRING
    first_name = DEFAULT_STRING
    last_name = DEFAULT_STRING
    email = DEFAULT_STRING
    is_staff = False
    is_active = True
    date_joined = DEFAULT_DT


class CveLabelFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = CveLabel
        django_get_or_create = ("cve_label_id",)

    cve_label_id = 1
    cve_label_code = "todo"
    cve_label_name = "要対応"
    display_order = 1
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT


class UserCveLabelFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = UserCveLabel

    id = None
    user = factory.SubFactory(UserFactory)
    cve = factory.SubFactory(CveFactory)
    cve_label = factory.SubFactory(CveLabelFactory)
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT


class UserKeywordFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = UserKeyword

    id = None
    user = factory.SubFactory(UserFactory)
    keyword = DEFAULT_STRING
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT


class UserCveCommentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = UserCveComment

    id = None
    user = factory.SubFactory(UserFactory)
    cve = factory.SubFactory(CveFactory)
    cve_comment = DEFAULT_STRING
    created_by = DEFAULT_STRING
    created_at = DEFAULT_DT
    updated_by = DEFAULT_STRING
    updated_at = DEFAULT_DT
