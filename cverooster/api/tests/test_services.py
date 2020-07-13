from django.test import TransactionTestCase

from api.services import CveListAPIService
from api.tests.factories import (
    CveFactory,
    CveLabelFactory,
    Cvss2Factory,
    Cvss3Factory,
    UserCveCommentFactory,
    UserCveLabelFactory,
    UserFactory,
    UserKeywordFactory,
)
from core.models import AppUser, Cve, CveLabel, Cvss2, Cvss3


class TestCveListAPIService(TransactionTestCase):
    """CveListAPIServiceのテストクラス

    ※ TestCaseではなくTransactionTestCaseを使用する理由。
        cve_full_text_search.cve_text_for_searchはMySQLのFULLTEXTインデックスを使用している。
        > https://dev.mysql.com/doc/refman/5.6/ja/innodb-fulltext-index.html

        MySQLのFULLTEXTインデックスはコミット時にインデックスが作成される仕様であるため、
        都度コミットするTransactionTestCaseを使用する必要がある。
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
        # test cve data
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
        CveFactory.create(
            cve_id="CVE-2020-0001", cve_year=2020, cve_number=1,
        )
        CveFactory.create(
            cve_id="CVE-2019-0003",
            cve_year=2019,
            cve_number=3,
            cve_full_text_search__cve_text_for_search="apple Python apple",
        )
        CveFactory.create(
            cve_id="CVE-2019-0004",
            cve_year=2019,
            cve_number=4,
            cve_full_text_search__cve_text_for_search="apple Ruby apple",
        )
        CveFactory.create(
            cve_id="CVE-2019-0005",
            cve_year=2019,
            cve_number=5,
            cvss3=Cvss3Factory.build(cvss3_severity_code="CRITICAL"),
        )
        CveFactory.create(
            cve_id="CVE-2019-0006",
            cve_year=2019,
            cve_number=6,
            cvss2=Cvss2Factory.build(cvss2_severity_code="HIGH"),
        )
        # test user data
        UserFactory.create(username="user1")
        UserCveLabelFactory.create(
            user=UserFactory(username="user1"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        UserFactory.create(username="user2")
        UserCveLabelFactory.create(
            user=UserFactory(username="user2"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_label=CveLabelFactory(cve_label_id=1),
        )
        UserCveLabelFactory.create(
            user=UserFactory(username="user2"),
            cve=CveFactory(cve_id="CVE-2019-0002"),
            cve_label=CveLabelFactory(cve_label_id=2),
        )
        UserFactory.create(username="user3")
        UserKeywordFactory.create(user=UserFactory(username="user3"), keyword="ruby")
        UserFactory.create(username="user4")
        UserKeywordFactory.create(user=UserFactory(username="user4"), keyword="ruby")
        UserKeywordFactory.create(user=UserFactory(username="user4"), keyword="python")
        UserFactory.create(username="user5")
        UserCveCommentFactory.create(
            user=UserFactory(username="user5"),
            cve=CveFactory(cve_id="CVE-2019-0001"),
            cve_comment="fizzbuzz",
        )

    def test_severity_is_MEDIUM(self):
        service = CveListAPIService()
        result = service.find_cve_list(
            severity="MEDIUM",
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
        )
        self.assertEqual(result.total_count, 4)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0006")
        self.assertEqual(result.cve_list[1].cve_id, "CVE-2019-0005")
        self.assertEqual(result.cve_list[2].cve_id, "CVE-2019-0002")
        self.assertEqual(result.cve_list[3].cve_id, "CVE-2019-0001")

    def test_severity_is_HIGH(self):
        service = CveListAPIService()
        result = service.find_cve_list(
            severity="HIGH", year=None, keyword=None, page=1, display_count_per_page=10,
        )
        self.assertEqual(result.total_count, 3)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0006")
        self.assertEqual(result.cve_list[1].cve_id, "CVE-2019-0005")
        self.assertEqual(result.cve_list[2].cve_id, "CVE-2019-0002")

    def test_severity_is_CRITICAL(self):
        service = CveListAPIService()
        result = service.find_cve_list(
            severity="CRITICAL",
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
        )
        self.assertEqual(result.total_count, 1)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0005")

    def test_year_is_2020(self):
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=2020, keyword=None, page=1, display_count_per_page=10,
        )
        self.assertEqual(result.total_count, 1)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2020-0001")

    def test_keyword_is_Python(self):
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword="Python",
            page=1,
            display_count_per_page=10,
        )
        self.assertEqual(result.total_count, 1)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0003")

    def test_keyword_is_python(self):
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword="python",
            page=1,
            display_count_per_page=10,
        )
        self.assertEqual(result.total_count, 1)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0003")

    def test_user_cve_label_is_1(self):
        service = CveListAPIService()
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user1")
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
            user_id=user_id,
            labels=[1],
        )
        self.assertEqual(result.total_count, 1)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0001")
        self.assertEqual(result.cve_list[0].label_id, 1)

    def test_user_cve_label_is_12(self):
        service = CveListAPIService()
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user2")
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
            user_id=user_id,
            labels=[1, 2],
        )
        self.assertEqual(result.total_count, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0002")
        self.assertEqual(result.cve_list[0].label_id, 2)
        self.assertEqual(result.cve_list[1].cve_id, "CVE-2019-0001")
        self.assertEqual(result.cve_list[1].label_id, 1)

    def test_user_keyword_is_ruby(self):
        service = CveListAPIService()
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user3")
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
            user_id=user_id,
            enable_user_keyword=True,
        )
        self.assertEqual(result.total_count, 1)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0004")

    def test_user_keyword_is_ruby_and_python(self):
        service = CveListAPIService()
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user4")
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
            user_id=user_id,
            enable_user_keyword=True,
        )
        self.assertEqual(result.total_count, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0004")
        self.assertEqual(result.cve_list[1].cve_id, "CVE-2019-0003")

    def test_user_keyword_is_ruby_and_keyword_is_python(self):
        service = CveListAPIService()
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user3")
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword="python",
            page=1,
            display_count_per_page=10,
            user_id=user_id,
            enable_user_keyword=True,
        )
        self.assertEqual(result.total_count, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0004")
        self.assertEqual(result.cve_list[1].cve_id, "CVE-2019-0003")

    def test_enable_user_keyword_is_True_and_user_keyword_is_empty(self):
        service = CveListAPIService()
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user1")
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
            user_id=user_id,
            enable_user_keyword=True,
        )
        self.assertEqual(result.total_count, 0)

    def test_user_cve_comment_is_fizzbuzz(self):
        service = CveListAPIService()
        user_id = AppUser.objects.values_list("id", flat=True).get(username="user5")
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10,
            user_id=user_id,
        )
        self.assertEqual(result.cve_list[-1].cve_id, "CVE-2019-0001")
        self.assertEqual(result.cve_list[-1].comment, "fizzbuzz")

    def test_no_condition(self):
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None,
            year=None,
            keyword=None,
            page=1,
            display_count_per_page=10000,
        )
        expected = Cve.objects.all().count()
        self.assertEqual(result.total_count, expected)

    def test_paging_10(self):
        Cve.objects.all().delete()
        for i in range(1, 11):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=None, keyword=None, page=1, display_count_per_page=10,
        )
        self.assertEqual(result.display_count_from, 1)
        self.assertEqual(result.display_count_to, 10)
        self.assertEqual(result.current_page, 1)
        self.assertEqual(result.max_page, 1)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0010")
        self.assertEqual(result.cve_list[9].cve_id, "CVE-2019-0001")

    def test_paging_11_1(self):
        Cve.objects.all().delete()
        for i in range(1, 12):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=None, keyword=None, page=1, display_count_per_page=10,
        )
        self.assertEqual(result.display_count_from, 1)
        self.assertEqual(result.display_count_to, 10)
        self.assertEqual(result.current_page, 1)
        self.assertEqual(result.max_page, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0011")
        self.assertEqual(result.cve_list[9].cve_id, "CVE-2019-0002")

    def test_paging_11_2(self):
        Cve.objects.all().delete()
        for i in range(1, 12):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=None, keyword=None, page=2, display_count_per_page=10,
        )
        self.assertEqual(result.display_count_from, 11)
        self.assertEqual(result.display_count_to, 11)
        self.assertEqual(result.current_page, 2)
        self.assertEqual(result.max_page, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0001")

    def test_paging_12_2(self):
        Cve.objects.all().delete()
        for i in range(1, 13):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=None, keyword=None, page=2, display_count_per_page=10,
        )
        self.assertEqual(result.display_count_from, 11)
        self.assertEqual(result.display_count_to, 12)
        self.assertEqual(result.current_page, 2)
        self.assertEqual(result.max_page, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0002")
        self.assertEqual(result.cve_list[1].cve_id, "CVE-2019-0001")

    def test_paging_20_1(self):
        Cve.objects.all().delete()
        for i in range(1, 21):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=None, keyword=None, page=1, display_count_per_page=10,
        )
        self.assertEqual(result.display_count_from, 1)
        self.assertEqual(result.display_count_to, 10)
        self.assertEqual(result.current_page, 1)
        self.assertEqual(result.max_page, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0020")
        self.assertEqual(result.cve_list[9].cve_id, "CVE-2019-0011")

    def test_paging_20_2(self):
        Cve.objects.all().delete()
        for i in range(1, 21):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=None, keyword=None, page=2, display_count_per_page=10,
        )
        self.assertEqual(result.display_count_from, 11)
        self.assertEqual(result.display_count_to, 20)
        self.assertEqual(result.current_page, 2)
        self.assertEqual(result.max_page, 2)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0010")
        self.assertEqual(result.cve_list[9].cve_id, "CVE-2019-0001")

    def test_paging_21_3(self):
        Cve.objects.all().delete()
        for i in range(1, 22):
            CveFactory.create(cve_id=f"CVE-2019-{i:04}", cve_year=2019, cve_number=i)
        service = CveListAPIService()
        result = service.find_cve_list(
            severity=None, year=None, keyword=None, page=3, display_count_per_page=10,
        )
        self.assertEqual(result.display_count_from, 21)
        self.assertEqual(result.display_count_to, 21)
        self.assertEqual(result.current_page, 3)
        self.assertEqual(result.max_page, 3)
        self.assertEqual(result.cve_list[0].cve_id, "CVE-2019-0001")
