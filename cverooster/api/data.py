from dataclasses import dataclass
from datetime import datetime
from typing import List


@dataclass
class Result:
    pass


@dataclass(frozen=True)
class ExpectedErrorAPIResponse:
    code: str
    error_messages: List[str]
    result: dict


@dataclass(frozen=True)
class UnexpectedErrorAPIResponse:
    code: str
    error_messages: List[str]
    result: dict


@dataclass(frozen=True)
class OKAPIResponse:
    code: str
    error_messages: List[str]
    result: Result


@dataclass
class CveRecord:
    cve_id: str
    cve_url: str
    nvd_url: str
    nvd_content_exists: bool
    cve_description: str
    cvss3_score: float
    cvss3_severity: str
    cvss2_score: float
    cvss2_severity: str
    published_date: datetime
    label_id: int
    comment: str


@dataclass
class CveListResult(Result):
    total_count: int
    display_count_from: int
    display_count_to: int
    current_page: int
    max_page: int
    cve_list: List[CveRecord]
