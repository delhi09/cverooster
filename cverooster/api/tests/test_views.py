from datetime import date
import json

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APITransactionTestCase

from api.tests.factories import (
    DEFAULT_DT,
    DEFAULT_STRING,
    CveFactory,
    CveLabelFactory,
    Cvss2Factory,
    Cvss3Factory,
    UserCveCommentFactory,
    UserCveLabelFactory,
    UserFactory,
    UserKeywordFactory,
)
from core.models import (
    AppUser,
    CveLabel,
    Cvss2,
    Cvss3,
    UserCveComment,
    UserCveLabel,
    UserKeyword,
)


class TestCveListAPIView(APITransactionTestCase):
    """CveListAPIViewのテストクラス

    ※ APITestCaseではなくAPITransactionTestCaseを使用する理由。
        cve_full_text_search.cve_text_for_searchはMySQLのFULLTEXTインデックスを使用している。
        > https://dev.mysql.com/doc/refman/5.6/ja/innodb-fulltext-index.html

        MySQLのFULLTEXTインデックスはコミット時にインデックスが作成される仕様であるため、
        都度コミットするAPITransactionTestCaseを使用する必要がある。
        > https://stackoverflow.com/questions/16790705/django-unittesting-fulltext-search
    """

    @classmethod
    def setUp(cls):
        # clean migration data
        Cvss3.objects.all().delete()
        Cvss2.objects.all().delete()
        CveLabel.objects.all().delete()
        # master data
        Cvss3Factory.create(cvss3_severity_code="NONE", cvss3_severity_level=1)
        Cvss3Factory.create(cvss3_severity_code="LOW", cvss3_severity_level=2)
        Cvss3Factory.create(cvss3_severity_code="MEDIUM", cvss3_severity_level=3)
        Cvss3Factory.create(cvss3_severity_code="HIGH", cvss3_severity_level=4)
        Cvss3Factory.create(cvss3_severity_code="CRITICAL", cvss3_severity_level=5)
        Cvss2Factory.create(cvss2_severity_code="LOW", cvss2_severity_level=1)
        Cvss2Factory.create(cvss2_severity_code="MEDIUM", cvss2_severity_level=2)
        Cvss2Factory.create(cvss2_severity_code="HIGH", cvss2_severity_level=3)
        CveLabel.objects.all().delete()
        CveLabelFactory.create(
            cve_label_id=1, cve_label_code="todo", cve_label_name="要対応"
        )
        CveLabelFactory.create(
            cve_label_id=2, cve_label_code="not_required", cve_label_name="対応不要"
        )
        CveLabelFactory.create(
            cve_label_id=3, cve_label_code="done", cve_label_name="対応済み"
        )

    def test_normal_nologin(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        response = self.client.get(reverse("cverooster_api:cve_list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        response_body = json.loads(response.content)
        self.assertEqual(response_body["code"], "ok")
        self.assertEqual(response_body["error_messages"], [])
        result = response_body["result"]
        self.assertEqual(result["total_count"], 1)
        self.assertEqual(result["display_count_from"], 1)
        self.assertEqual(result["display_count_to"], 1)
        self.assertEqual(result["current_page"], 1)
        self.assertEqual(result["max_page"], 1)
        cve_list = result["cve_list"]
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0001")
        self.assertEqual(cve0["cve_url"], DEFAULT_STRING)
        self.assertEqual(cve0["nvd_url"], DEFAULT_STRING)
        self.assertTrue(cve0["nvd_content_exists"])
        self.assertEqual(cve0["cve_description"], DEFAULT_STRING)
        self.assertEqual(cve0["cvss3_score"], 1.0)
        self.assertEqual(cve0["cvss3_severity"], "LOW")
        self.assertEqual(cve0["cvss2_score"], 1.0)
        self.assertEqual(cve0["cvss2_severity"], "LOW")
        self.assertIsNotNone(cve0["published_date"])
        self.assertIsNone(cve0["label_id"])
        self.assertIsNone(cve0["comment"])

    def test_normal_login(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        UserCveCommentFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_comment="fizzbuzz",
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        response = self.client.get(reverse("cverooster_api:cve_list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        response_body = json.loads(response.content)
        self.assertEqual(response_body["code"], "ok")
        self.assertEqual(response_body["error_messages"], [])
        result = response_body["result"]
        self.assertEqual(result["total_count"], 1)
        self.assertEqual(result["display_count_from"], 1)
        self.assertEqual(result["display_count_to"], 1)
        self.assertEqual(result["current_page"], 1)
        self.assertEqual(result["max_page"], 1)
        cve_list = result["cve_list"]
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0001")
        self.assertEqual(cve0["cve_url"], DEFAULT_STRING)
        self.assertEqual(cve0["nvd_url"], DEFAULT_STRING)
        self.assertTrue(cve0["nvd_content_exists"])
        self.assertEqual(cve0["cve_description"], DEFAULT_STRING)
        self.assertEqual(cve0["cvss3_score"], 1.0)
        self.assertEqual(cve0["cvss3_severity"], "LOW")
        self.assertEqual(cve0["cvss2_score"], 1.0)
        self.assertEqual(cve0["cvss2_severity"], "LOW")
        self.assertIsNotNone(cve0["published_date"])
        self.assertEqual(cve0["label_id"], 1)
        self.assertEqual(cve0["comment"], "fizzbuzz")

    def test_severity_is_HIGH(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
            cvss3=Cvss3Factory.build(cvss3_severity_code="MEDIUM"),
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
            cvss3=Cvss3Factory.build(cvss3_severity_code="HIGH"),
        )
        params = ["severity=HIGH"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 1)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0002")

    def test_severity_is_invalid(self):
        invalid_params_list = [
            ["severity=DUMMY"],
            ["severity=High"],
            ["severity=aHIGHb"],
            ["severity=HIGHb"],
            ["severity=aHIGH"],
            ["severity=1"],
            ["severity=None"],
            ["severity=True"],
        ]
        for params in invalid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_severity_is_valid(self):
        valid_params_list = [
            ["severity=LOW"],
            ["severity=MEDIUM"],
            ["severity=HIGH"],
            ["severity=CRITICAL"],
            ["severity="],
        ]
        for params in valid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_year_is_2020(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        CveFactory.create(
            cve_id="CVE-2020-0001",
            cve_year=2020,
            cve_number=1,
        )
        params = ["year=2020"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 1)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2020-0001")

    def test_year_is_invalid(self):
        invalid_params_list = [
            ["year=DUMMY"],
            ["year=1994"],
            ["year=" + str(date.today().year + 1)],
            ["year=None"],
            ["year=True"],
        ]
        for params in invalid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_year_is_valid(self):
        valid_params_list = [
            ["year=1995"],
            ["year=" + str(date.today().year)],
            ["year="],
        ]
        for params in valid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_page_is_2(self):
        for i in range(1, 12):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        params = ["page=2"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 1)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0001")

    def test_page_is_invalid(self):
        invalid_params_list = [
            ["page=DUMMY"],
            ["page=0"],
            ["page=100001"],
            ["page=None"],
            ["page=True"],
        ]
        for params in invalid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_page_is_valid(self):
        valid_params_list = [
            ["page=1"],
            ["page=100000"],
        ]
        for params in valid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_keyword_is_python(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
            cve_full_text_search__cve_text_for_search="Python",
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
        )
        params = ["keyword=python"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 1)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0001")

    def test_keyword_is_invalid(self):
        invalid_params_list = [
            ["keyword=."],
            ["keyword=)"],
            ["keyword=@"],
            ["keyword=Ab1@"],
            ["keyword=" + ("a" * 33)],
        ]
        for params in invalid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_keyword_is_valid(self):
        valid_params_list = [
            ["keyword=a"],
            ["keyword=A"],
            ["keyword=0"],
            ["keyword=1"],
            ["keyword=Ab1"],
            ["keyword=None"],
            ["keyword=null"],
            ["keyword=True"],
            ["keyword="],
            ["keyword=" + ("a" * 32)],
        ]
        for params in valid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_label_is_1(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
        )
        CveFactory.create(
            cve_id="CVE-2019-0003",
            cve_year=2019,
            cve_number=3,
        )
        UserFactory.create(username="user", password="password")
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0002"),
            cve_label=CveLabelFactory(cve_label_id=2),
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        params = ["label=1"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 1)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0001")

    def test_label_is_1_nologin(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
        )
        CveFactory.create(
            cve_id="CVE-2019-0003",
            cve_year=2019,
            cve_number=3,
        )
        UserFactory.create(username="user", password="password")
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0002"),
            cve_label=CveLabelFactory(cve_label_id=2),
        )
        params = ["label=1"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 3)

    def test_label_is_1_and_2(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
        )
        CveFactory.create(
            cve_id="CVE-2019-0003",
            cve_year=2019,
            cve_number=3,
        )
        UserFactory.create(username="user", password="password")
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0002"),
            cve_label=CveLabelFactory(cve_label_id=2),
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        params = ["label=1", "label=2"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 2)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0002")
        cve0 = cve_list[1]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0001")

    def test_label_is_invalid(self):
        invalid_params_list = [
            ["label=DUMMY"],
            ["label=0"],
            ["label=5"],
            ["label=1,2"],
            ["label=1", "label=5"],
            ["label=None"],
            ["label=null"],
            ["label=True"],
        ]
        for params in invalid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                status.HTTP_400_BAD_REQUEST,
                response.status_code,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_label_is_valid(self):
        valid_params_list = [
            ["label=1"],
            ["label=2"],
            ["label=3"],
            ["label=4"],
            ["label=1", "label=2"],
        ]
        for params in valid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_enable_user_keyword_is_true(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
            cve_full_text_search__cve_text_for_search="Python",
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
        )
        UserFactory.create(username="user", password="password")
        UserKeywordFactory.create(
            user=UserFactory(username="user", password="password"), keyword="Python"
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        params = ["enable_user_keyword=true"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 1)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0001")

    def test_enable_user_keyword_is_false(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
            cve_full_text_search__cve_text_for_search="Python",
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
        )
        UserFactory.create(username="user", password="password")
        UserKeywordFactory.create(
            user=UserFactory(username="user", password="password"), keyword="Python"
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        params = ["enable_user_keyword=false"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 2)

    def test_enable_user_keyword_is_true_nologin(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
            cve_full_text_search__cve_text_for_search="Python",
        )
        CveFactory.create(
            cve_id="CVE-2019-0002",
            cve_year=2019,
            cve_number=2,
        )
        UserFactory.create(username="user", password="password")
        UserKeywordFactory.create(
            user=UserFactory(username="user", password="password"), keyword="Python"
        )
        params = ["enable_user_keyword=true"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_body = json.loads(response.content)
        result = response_body["result"]
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 2)

    def test_enable_user_keyword_is_invalid(self):
        invalid_params_list = [
            ["enable_user_keyword=DUMMY"],
            ["enable_user_keyword=2"],
            ["label=None"],
            ["label=null"],
        ]
        for params in invalid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_enable_user_keyword_is_valid(self):
        valid_params_list = [
            ["enable_user_keyword=0"],
            ["enable_user_keyword=1"],
            ["enable_user_keyword=true"],
            ["enable_user_keyword=True"],
            ["enable_user_keyword=false"],
            ["enable_user_keyword=False"],
        ]
        for params in valid_params_list:
            response = self.client.get(
                reverse("cverooster_api:cve_list") + "?" + "&".join(params)
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "params=" + str(params) + " returns " + str(response.status_code),
            )

    def test_total_is_12_and_page_is_2(self):
        for i in range(1, 13):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        params = ["page=2"]
        response = self.client.get(
            reverse("cverooster_api:cve_list") + "?" + "&".join(params)
        )
        response_body = json.loads(response.content)
        result = response_body["result"]
        self.assertEqual(result["total_count"], 12)
        self.assertEqual(result["display_count_from"], 11)
        self.assertEqual(result["display_count_to"], 12)
        self.assertEqual(result["current_page"], 2)
        self.assertEqual(result["max_page"], 2)
        cve_list = result["cve_list"]
        self.assertEqual(len(cve_list), 2)
        cve0 = cve_list[0]
        self.assertEqual(cve0["cve_id"], "CVE-2019-0002")
        cve1 = cve_list[1]
        self.assertEqual(cve1["cve_id"], "CVE-2019-0001")


class TestSaveUserKeywordAPIView(APITestCase):
    def test_normal(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"keyword": "Python"}
        response = self.client.post(
            reverse("cverooster_api:save_user_keyword"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        user_keyword_list = UserKeyword.objects.filter(user__username="user")
        self.assertEqual(len(user_keyword_list), 1)
        user_keyword = user_keyword_list[0]
        self.assertEqual(user_keyword.keyword, "Python")
        self.assertEqual(user_keyword.created_by, "SaveUserKeywordAPI")
        self.assertIsNotNone(user_keyword.created_at)
        self.assertEqual(user_keyword.updated_by, "SaveUserKeywordAPI")
        self.assertIsNotNone(user_keyword.updated_at)

    def test_resource_exist(self):
        UserFactory.create(username="user", password="password")
        UserKeywordFactory.create(
            user=UserFactory(username="user", password="password"), keyword="Python"
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"keyword": "Python"}
        response = self.client.post(
            reverse("cverooster_api:save_user_keyword"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_nologin(self):
        UserFactory.create(username="user", password="password")
        post_data = {"keyword": "Python"}
        response = self.client.post(
            reverse("cverooster_api:save_user_keyword"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_no_keyword(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        response = self.client.post(reverse("cverooster_api:save_user_keyword"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_keyword_is_valid(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        valid_keyword_list = [
            "a",
            "B",
            "0",
            "1",
            "Ab1",
            "None",
            "null",
            "True",
            "a" * 32,
        ]
        for keyword in valid_keyword_list:
            post_data = {"keyword": keyword}
            response = self.client.post(
                reverse("cverooster_api:save_user_keyword"), post_data
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "keyword=" + keyword + " returns " + str(response.status_code),
            )
            self.assertEqual(response["Content-Type"], "application/json")

    def test_keyword_is_invalid(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        invalid_keyword_list = [".", ")", "@", "Ab1@", "", "a" * 33]
        for keyword in invalid_keyword_list:
            post_data = {"keyword": keyword}
            response = self.client.post(
                reverse("cverooster_api:save_user_keyword"), post_data
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                "keyword=" + keyword + " returns " + str(response.status_code),
            )
            self.assertEqual(response["Content-Type"], "application/json")

    def test_keyword_count_is_50(self):
        UserFactory.create(username="user", password="password")
        for i in range(1, 50):
            UserKeywordFactory.create(
                user=UserFactory(username="user", password="password"), keyword=str(i)
            )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"keyword": "50"}
        response = self.client.post(
            reverse("cverooster_api:save_user_keyword"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_keyword_count_is_51(self):
        UserFactory.create(username="user", password="password")
        for i in range(1, 51):
            UserKeywordFactory.create(
                user=UserFactory(username="user", password="password"), keyword=str(i)
            )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"keyword": "51"}
        response = self.client.post(
            reverse("cverooster_api:save_user_keyword"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")


class TestDeleteUserKeywordAPIView(APITestCase):
    def test_normal(self):
        UserFactory.create(username="user", password="password")
        UserKeywordFactory.create(
            user=UserFactory(username="user", password="password"), keyword="Python"
        )
        self.assertTrue(AppUser.objects.filter(username="user").exists())
        self.assertTrue(
            UserKeyword.objects.filter(user__username="user", keyword="Python").exists()
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"keyword": "Python"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_keyword"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertTrue(AppUser.objects.filter(username="user").exists())
        self.assertFalse(
            UserKeyword.objects.filter(user__username="user", keyword="Python").exists()
        )

    def test_resource_not_exist(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"keyword": "Python"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_keyword"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_nologin(self):
        UserFactory.create(username="user", password="password")
        delete_data = {"keyword": "Python"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_keyword"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_no_keyword(self):
        UserFactory.create(username="user", password="password")
        UserKeywordFactory.create(
            user=UserFactory(username="user", password="password"), keyword="Python"
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        response = self.client.delete(reverse("cverooster_api:delete_user_keyword"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_keyword_is_valid(self):
        UserFactory.create(username="user", password="password")
        valid_keyword_list = [
            "a",
            "B",
            "0",
            "1",
            "Ab1",
            "None",
            "null",
            "True",
            "a" * 32,
        ]
        for keyword in valid_keyword_list:
            UserKeywordFactory.create(
                user=UserFactory(username="user", password="password"), keyword=keyword
            )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        for keyword in valid_keyword_list:
            delete_data = {"keyword": keyword}
            response = self.client.delete(
                reverse("cverooster_api:delete_user_keyword"), delete_data
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK,
                "keyword=" + keyword + " returns " + str(response.status_code),
            )
            self.assertEqual(response["Content-Type"], "application/json")

    def test_keyword_is_invalid(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        invalid_keyword_list = [".", ")", "@", "Ab1@", "", "a" * 33]
        for keyword in invalid_keyword_list:
            delete_data = {"keyword": keyword}
            response = self.client.delete(
                reverse("cverooster_api:delete_user_keyword"), delete_data
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_400_BAD_REQUEST,
                "keyword=" + keyword + " returns " + str(response.status_code),
            )
            self.assertEqual(response["Content-Type"], "application/json")


class TestSaveUserCveCommentAPIView(APITestCase):
    def test_normal_insert(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "comment": "fizzbuzz"}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_comment"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        user_cve_comment = UserCveComment.objects.get(
            cve__cve_id="CVE-2019-0001", user__username="user"
        )
        self.assertEqual(user_cve_comment.cve_comment, "fizzbuzz")

    def test_normal_update(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        UserCveCommentFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_comment="fizzbuzz",
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "comment": "fizz"}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_comment"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        user_cve_comment = UserCveComment.objects.get(
            cve__cve_id="CVE-2019-0001", user__username="user"
        )
        self.assertEqual(user_cve_comment.cve_comment, "fizz")

    def test_resource_not_exist(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "comment": "fizzbuzz"}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_comment"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_comment_over_max_length(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "comment": "a" * 256}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_comment"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")


class TestDeleteUserCveCommentAPIView(APITestCase):
    def test_normal_delete(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        UserCveCommentFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_comment="fizzbuzz",
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"cve_id": "CVE-2019-0001"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_comment"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertFalse(
            UserCveComment.objects.filter(
                cve__cve_id="CVE-2019-0001", user__username="user"
            ).exists()
        )

    def test_resource_not_exist(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"cve_id": "CVE-2019-0001"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_comment"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_nologin(self):
        UserFactory.create(username="user", password="password")
        delete_data = {"cve_id": "CVE-2019-0001"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_comment"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_no_cve_id(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        response = self.client.delete(reverse("cverooster_api:delete_user_cve_comment"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_cve_id_invalid_format(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"cve_id": "aaa"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_comment"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")


class TestSaveUserCveLabelAPIView(APITestCase):
    def test_normal_insert(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "label": 1}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_label"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user")
        user_cve_label = UserCveLabel.objects.get(
            user__id=user_id, cve__cve_id="CVE-2019-0001"
        )
        self.assertEqual(user_cve_label.cve_label.cve_label_id, 1)

    def test_normal_update(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "label": 2}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_label"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user")
        user_cve_label = UserCveLabel.objects.get(
            user__id=user_id, cve__cve_id="CVE-2019-0001"
        )
        self.assertEqual(user_cve_label.cve_label.cve_label_id, 2)

    def test_nologin(self):
        UserFactory.create(username="user", password="password")
        post_data = {"cve_id": "CVE-2019-0001", "label": 1}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_label"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_resource_not_exist(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "label": 1}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_label"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_label_is_invalid(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        post_data = {"cve_id": "CVE-2019-0001", "label": 5}
        response = self.client.post(
            reverse("cverooster_api:save_user_cve_label"), post_data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")


class TestDeleteUserCveLabelAPIView(APITestCase):
    def test_normal_delete(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        UserCveLabelFactory.create(
            user=UserFactory(username="user", password="password"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"cve_id": "CVE-2019-0001"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_label"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertFalse(
            UserCveLabel.objects.filter(
                cve__cve_id="CVE-2019-0001", user__username="user"
            ).exists()
        )

    def test_resource_not_exist(self):
        CveFactory.create(
            cve_id="CVE-2019-0001",
            cve_year=2019,
            cve_number=1,
        )
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"cve_id": "CVE-2019-0001"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_label"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_nologin(self):
        UserFactory.create(username="user", password="password")
        delete_data = {"cve_id": "CVE-2019-0001"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_label"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_no_cve_id(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        response = self.client.delete(reverse("cverooster_api:delete_user_cve_label"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_cve_id_invalid_format(self):
        UserFactory.create(username="user", password="password")
        logged_in = self.client.login(username="user", password="password")
        self.assertTrue(logged_in)
        delete_data = {"cve_id": "aaa"}
        response = self.client.delete(
            reverse("cverooster_api:delete_user_cve_label"), delete_data
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response["Content-Type"], "application/json")
