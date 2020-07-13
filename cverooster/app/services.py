from django.utils import timezone

from app.data import (
    CveDetailViewContext,
    CveLabelOption,
    CveListViewContext,
    CveSeverityOption,
    CvssRisk,
    Link,
    UserFilterSettings,
    UserKeywordListViewContext,
    UserSettingsSaveData,
    UserSettingsViewContext,
)
from core.models import (
    AppUser,
    Cve,
    CveLabel,
    CveSeverity,
    UserFilterSetting,
    UserFilterSettingCveLabel,
    UserKeyword,
    UserMailAddress,
    UserSlackWebhookUrl,
)


class CveDetailService:
    RISK_LOW = "LOW"
    RISK_MEDIUM = "MEDIUM"
    RISK_HIGH = "HIGH"

    def create_cve_detail_view_context(self, cve_id):
        cve = Cve.objects.filter(cve_id=cve_id).first()

        cvss3_risk_list = (
            self._create_cvss3_risk_list(cve.cvss3_vector) if cve.cvss3_vector else []
        )
        cvss2_risk_list = (
            self._create_cvss2_risk_list(cve.cvss2_vector) if cve.cvss2_vector else []
        )
        context = CveDetailViewContext(
            cve_id=cve.cve_id,
            cve_description=cve.cve_description,
            cvss3_score=cve.cvss3_score,
            cvss3_severity=cve.cvss3.cvss3_severity_code if cve.cvss3 else None,
            cvss3_risk_list=cvss3_risk_list,
            cvss2_score=cve.cvss2_score,
            cvss2_severity=cve.cvss2.cvss2_severity_code if cve.cvss2 else None,
            cvss2_risk_list=cvss2_risk_list,
            published_date=cve.published_date,
            updated_date=cve.last_modified_date,
            links=self._create_links(cve.cve_id),
        )
        return context

    def _create_links(self, cve_id):
        cve_link = Link(
            title="CVE(外部サイト)",
            url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
        )
        nvd_link = Link(
            title="NVD(外部サイト)", url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        )
        return [cve_link, nvd_link]

    def _create_cvss3_risk_list(self, cvss3_vector):
        cvss3_risk_list = []
        items = cvss3_vector.split("/")
        for item in items:
            columns = item.split(":")
            if len(columns) != 2:
                continue
            item_name = columns[0]
            item_full_name = self.get_item_full_name(item_name)
            if item_full_name is None:
                continue
            result = columns[1]
            risk = self._calc_cvss3_risk(item_name, result)
            if risk is None:
                continue
            cvss3_risk_list.append(
                CvssRisk(
                    title=item_full_name,
                    percentage=self._calc_risk_percentage(risk),
                    expr=self._calc_risk_expr(risk),
                    bar_color=self._calc_risk_bar_color(risk),
                )
            )
        return cvss3_risk_list

    def _create_cvss2_risk_list(self, cvss2_vector):
        cvss2_risk_list = []
        cvss2_vector = cvss2_vector.replace("(", "").replace(")", "")
        items = cvss2_vector.split("/")
        for item in items:
            columns = item.split(":")
            if len(columns) != 2:
                continue
            item_name = columns[0]
            item_full_name = self.get_item_full_name(item_name)
            if item_full_name is None:
                continue
            result = columns[1]
            risk = self._calc_cvss2_risk(item_name, result)
            if risk is None:
                continue
            cvss2_risk_list.append(
                CvssRisk(
                    title=item_full_name,
                    percentage=self._calc_risk_percentage(risk),
                    expr=self._calc_risk_expr(risk),
                    bar_color=self._calc_risk_bar_color(risk),
                )
            )
        return cvss2_risk_list

    def _calc_risk_percentage(self, risk):
        calc_table = {self.RISK_HIGH: 75, self.RISK_MEDIUM: 50, self.RISK_LOW: 25}
        return calc_table.get(risk)

    def _calc_risk_expr(self, risk):
        calc_table = {
            self.RISK_HIGH: "リスク高",
            self.RISK_MEDIUM: "リスク中",
            self.RISK_LOW: "リスク低",
        }
        return calc_table.get(risk)

    def _calc_risk_bar_color(self, risk):
        calc_table = {
            self.RISK_HIGH: "bg-danger",
            self.RISK_MEDIUM: "bg-warning",
            self.RISK_LOW: "bg-success",
        }
        return calc_table.get(risk)

    def _calc_cvss3_risk(self, item_name, result):
        calc_table = {
            # 攻撃元区分
            "AV": {
                "N": self.RISK_HIGH,
                "A": self.RISK_MEDIUM,
                "L": self.RISK_MEDIUM,
                "P": self.RISK_LOW,
            },
            # 攻撃条件の複雑さ
            "AC": {"L": self.RISK_HIGH, "H": self.RISK_LOW},
            # 必要な特権レベル
            "PR": {"N": self.RISK_HIGH, "L": self.RISK_MEDIUM, "H": self.RISK_LOW},
            # ユーザ関与レベル
            "UI": {"N": self.RISK_HIGH, "R": self.RISK_MEDIUM},
            # 機密性への影響
            "C": {"H": self.RISK_HIGH, "L": self.RISK_LOW, "N": self.RISK_LOW},
            # 完全性への影響
            "I": {"H": self.RISK_HIGH, "L": self.RISK_LOW, "N": self.RISK_LOW},
            # 可用性への影響
            "A": {"H": self.RISK_HIGH, "L": self.RISK_LOW, "N": self.RISK_LOW},
        }
        return calc_table.get(item_name, {}).get(result)

    def _calc_cvss2_risk(self, item_name, result):
        calc_table = {
            # 攻撃元区分
            "AV": {"N": self.RISK_HIGH, "A": self.RISK_MEDIUM, "L": self.RISK_LOW},
            # 攻撃条件の複雑さ
            "AC": {"L": self.RISK_HIGH, "M": self.RISK_LOW, "H": self.RISK_LOW},
            # 機密性への影響
            "C": {"C": self.RISK_HIGH, "P": self.RISK_LOW, "N": self.RISK_LOW},
            # 完全性への影響
            "I": {"C": self.RISK_HIGH, "P": self.RISK_LOW, "N": self.RISK_LOW},
            # 可用性への影響
            "A": {"C": self.RISK_HIGH, "P": self.RISK_LOW, "N": self.RISK_LOW},
        }
        return calc_table.get(item_name, {}).get(result)

    def get_item_full_name(self, item_name):
        full_name_table = {
            "AV": "攻撃元区分",
            "AC": "攻撃条件の複雑さ",
            "PR": "必要な特権レベル",
            "UI": "ユーザ関与レベル",
            "C": "機密性への影響",
            "I": "完全性への影響",
            "A": "可用性への影響",
        }
        return full_name_table.get(item_name)


class CveListService:
    def create_cve_list_view_context(self, user_id=None):
        cve_severity_options = self._create_cve_severity_options()
        cve_year_options = self._create_cve_year_options()
        cve_label_options = self._create_cve_label_options()
        user_filter_settings = (
            self._create_user_filter_settings(user_id) if user_id else None
        )
        context = CveListViewContext(
            cve_severity_options=cve_severity_options,
            cve_year_options=cve_year_options,
            cve_label_options=cve_label_options,
            user_filter_settings=user_filter_settings,
        )
        return context

    def _create_user_filter_settings(self, user_id):
        user_filter_setting = UserFilterSetting.objects.filter(user__id=user_id).first()
        if not user_filter_setting:
            return UserFilterSettings(
                severity=None, year=None, label_id_list=[], enable_user_keyword=True,
            )
        severity = (
            user_filter_setting.severity.cve_severity_code
            if user_filter_setting.severity is not None
            else None
        )
        year = user_filter_setting.year
        enable_user_keyword = user_filter_setting.enable_user_keyword
        user_filter_setting_cve_labels = UserFilterSettingCveLabel.objects.filter(
            user__id=user_id
        )
        label_id_list = [
            row.cve_label.cve_label_id for row in user_filter_setting_cve_labels
        ]
        return UserFilterSettings(
            severity=severity,
            year=year,
            label_id_list=label_id_list,
            enable_user_keyword=enable_user_keyword,
        )

    def _create_cve_severity_options(self):
        cve_severity_options = []
        for row in CveSeverity.objects.all().order_by("display_order"):
            cve_severity_options.append(
                CveSeverityOption(
                    cve_severity_code=row.cve_severity_code,
                    cve_severity_name=row.cve_severity_name,
                )
            )
        return cve_severity_options

    def _create_cve_year_options(self):
        return [2020, 2019, 2018]
        # max_year = Cve.objects.all().aggregate(Max("cve_year"))["cve_year__max"]
        # min_year = Cve.objects.all().aggregate(Min("cve_year"))["cve_year__min"]
        # return list(reversed(list(range(min_year, max_year + 1))))

    def _create_cve_label_options(self):
        cve_label_options = []
        for row in CveLabel.objects.all().order_by("display_order"):
            cve_label_options.append(
                CveLabelOption(
                    cve_label_id=row.cve_label_id,
                    cve_label_code=row.cve_label_code,
                    cve_label_name=row.cve_label_name,
                )
            )
        return cve_label_options


class UserKeywordListService:
    def create_user_keyword_list_context(self, user_id):
        user_keyword_list = (
            UserKeyword.objects.values_list("keyword", flat=True)
            .filter(user__id=user_id)
            .order_by("keyword")
        )
        context = UserKeywordListViewContext(user_keyword_list=user_keyword_list)
        return context


class UserSettingsViewService:
    def create_user_settings_context(self, user_id):
        cve_severity_options = self._create_cve_severity_options()
        cve_year_options = self._create_cve_year_options()
        cve_label_options = self._create_cve_label_options()
        user_settings_save_data = self._create_user_settings_save_data(user_id)
        context = UserSettingsViewContext(
            cve_severity_options=cve_severity_options,
            cve_year_options=cve_year_options,
            cve_label_options=cve_label_options,
            user_settings_save_data=user_settings_save_data,
            form=None,
        )
        return context

    def _create_user_settings_save_data(self, user_id):
        user_filter_setting = UserFilterSetting.objects.filter(user__id=user_id).first()
        severity = None
        if user_filter_setting and user_filter_setting.severity:
            severity = user_filter_setting.severity.cve_severity_code
        year = user_filter_setting.year if user_filter_setting else None
        enable_user_keyword = (
            user_filter_setting.enable_user_keyword if user_filter_setting else True
        )
        user_filter_setting_cve_labels = UserFilterSettingCveLabel.objects.filter(
            user__id=user_id
        )
        label_id_list = [
            row.cve_label.cve_label_id for row in user_filter_setting_cve_labels
        ]
        user_mail_address = UserMailAddress.objects.filter(user__id=user_id).first()
        mail_address = user_mail_address.mail_address if user_mail_address else None
        notify_mail = user_mail_address.notify_mail if user_mail_address else None
        user_slack_webhook_url = UserSlackWebhookUrl.objects.filter(
            user__id=user_id
        ).first()
        slack_webhook_url = (
            user_slack_webhook_url.slack_webhook_url if user_slack_webhook_url else None
        )
        notify_slack = (
            user_slack_webhook_url.notify_slack if user_slack_webhook_url else None
        )

        return UserSettingsSaveData(
            severity_code=severity,
            year=year,
            label_id_list=label_id_list,
            enable_user_keyword=enable_user_keyword,
            mail_address=mail_address,
            notify_mail=notify_mail,
            slack_webhook_url=slack_webhook_url,
            notify_slack=notify_slack,
        )

    def save_user_settings(self, user_id, user_settings):
        UserFilterSetting.objects.filter(user__id=user_id).delete()
        user = AppUser.objects.filter(id=user_id).first()
        current_timestamp = timezone.localtime(timezone.now())
        severity = None
        if user_settings.severity_code:
            severity = CveSeverity.objects.filter(
                cve_severity_code=user_settings.severity_code
            ).first()
        user_filter_setting = UserFilterSetting(
            user=user,
            severity=severity,
            year=user_settings.year,
            enable_user_keyword=user_settings.enable_user_keyword,
            created_by="UserSettings",
            created_at=current_timestamp,
            updated_by="UserSettings",
            updated_at=current_timestamp,
        )
        user_filter_setting.save()
        UserFilterSettingCveLabel.objects.filter(user__id=user_id).delete()
        if user_settings.label_id_list:
            for cve_label_id in user_settings.label_id_list:
                cve_label = CveLabel.objects.filter(cve_label_id=cve_label_id).first()
                user.cve_labels.add(cve_label)
        UserMailAddress.objects.filter(user__id=user_id).delete()
        if user_settings.mail_address:
            user_mail_address = UserMailAddress(
                user=user,
                mail_address=user_settings.mail_address,
                notify_mail=user_settings.notify_mail,
                created_by="UserSettings",
                created_at=current_timestamp,
                updated_by="UserSettings",
                updated_at=current_timestamp,
            )
            user_mail_address.save()
        UserSlackWebhookUrl.objects.filter(user__id=user_id).delete()
        if user_settings.slack_webhook_url:
            user_slack_webhook_url = UserSlackWebhookUrl(
                user=user,
                slack_webhook_url=user_settings.slack_webhook_url,
                notify_slack=user_settings.notify_slack,
                created_by="UserSettings",
                created_at=current_timestamp,
                updated_by="UserSettings",
                updated_at=current_timestamp,
            )
            user_slack_webhook_url.save()

    def _create_cve_severity_options(self):
        cve_severity_options = []
        for row in CveSeverity.objects.all().order_by("display_order"):
            cve_severity_options.append(
                CveSeverityOption(
                    cve_severity_code=row.cve_severity_code,
                    cve_severity_name=row.cve_severity_name,
                )
            )
        return cve_severity_options

    def _create_cve_year_options(self):
        return [2020, 2019, 2018]
        # max_year = Cve.objects.all().aggregate(Max("cve_year"))["cve_year__max"]
        # min_year = Cve.objects.all().aggregate(Min("cve_year"))["cve_year__min"]
        # return list(reversed(list(range(min_year, max_year + 1))))

    def _create_cve_label_options(self):
        cve_label_options = []
        for row in CveLabel.objects.all().order_by("display_order"):
            cve_label_options.append(
                CveLabelOption(
                    cve_label_id=row.cve_label_id,
                    cve_label_code=row.cve_label_code,
                    cve_label_name=row.cve_label_name,
                )
            )
        return cve_label_options
