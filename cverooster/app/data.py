from dataclasses import dataclass
from datetime import datetime
from typing import List

from app.forms import UserSettingsForm


@dataclass
class Link:
    url: str
    title: str


@dataclass
class CvssRisk:
    title: str
    percentage: int
    expr: str
    bar_color: str


@dataclass
class CveDetailViewContext:
    cve_id: str
    cve_description: str
    cvss3_score: float
    cvss3_severity: str
    cvss3_risk_list: List[CvssRisk]
    cvss2_score: float
    cvss2_severity: str
    cvss2_risk_list: List[CvssRisk]
    published_date: datetime
    updated_date: datetime
    links: List[Link]


@dataclass
class CveSeverityOption:
    cve_severity_code: str
    cve_severity_name: str


@dataclass
class CveLabelOption:
    cve_label_id: int
    cve_label_code: str
    cve_label_name: str


@dataclass
class UserFilterSettings:
    severity: str
    year: int
    label_id_list: List[int]
    enable_user_keyword: bool


@dataclass
class CveListViewContext:
    cve_severity_options: List[CveSeverityOption]
    cve_year_options: List[int]
    cve_label_options: List[CveLabelOption]
    user_filter_settings: UserFilterSettings


@dataclass
class UserKeywordListViewContext:
    user_keyword_list: List[str]


@dataclass
class UserSettingsSaveData:
    severity_code: str
    year: int
    label_id_list: List[int]
    enable_user_keyword: bool
    mail_address: str
    notify_mail: bool
    slack_webhook_url: str
    notify_slack: bool


@dataclass
class UserSettingsViewContext:
    cve_severity_options: List[CveSeverityOption]
    cve_year_options: List[str]
    cve_label_options: List[CveLabelOption]
    user_settings_save_data: UserSettingsSaveData
    form: UserSettingsForm
