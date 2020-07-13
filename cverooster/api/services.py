from django.db.models import Q

from api.data import CveListResult, CveRecord
from core.models import Cve, Cvss2, Cvss3, UserCveComment, UserCveLabel, UserKeyword


class CveListAPIService:
    def find_cve_list(
        self,
        severity,
        year,
        keyword,
        page,
        display_count_per_page,
        user_id=None,
        labels=None,
        enable_user_keyword=False,
    ):
        """CVE一覧取得APIの検索ロジック

        Args:
            severity (str): 検索条件とするCVEのseverityの下限。
                    「CRITICAL」、「HIGH」、「MEDIUM」、「LOW」のいずれか。
                    Noneの場合はCVEのseverityを検索条件に含めない。
            year (int): 検索条件とするCVEが発行された年の下限。
                    Noneの場合はCVEが発行された年を検索条件に含めない。
            keyword (str): 検索条件とするキーワード。
                    Noneの場合はキーワードを検索条件に含めない。
            page (int): 取得するページナンバー。
                    Noneは想定していない。
            display_count_per_page (int): 1ページあたりの表示件数。
                    Noneは想定していない。
            user_id (int): ユーザーID。
                    リクエストユーザーがログインしている場合は必須。
                    ログインしていない場合はNone。
            labels (List[int]): 検索条件とするユーザーがCVEに付与するラベルIDのリスト。
                    「1:要対応」、「2:対応不要」、「3:対応済み」のいずれか。
                    リクエストユーザーがログインしており、かつラベルを検索条件とする場合に渡される。
                    それ以外の場合はNone。
            enable_user_keyword (bool): ユーザーが登録しているキーワードを検索条件に含めるか否かの真偽値。
                    リクエストユーザーがログインしており、かつユーザーが登録しているキーワードを
                    検索条件とする場合にTrueが渡される。
                    それ以外の場合はFalse。

        Returns:
            CveListResult: CVE一覧取得API用の取得結果のデータクラス
        """
        cve_id_queryset = Cve.objects.values_list("cve_id", flat=True)
        if severity:
            try:
                cvss3_severity_level = Cvss3.objects.values_list(
                    "cvss3_severity_level", flat=True
                ).get(cvss3_severity_code=severity)
            except Cvss3.DoesNotExist:
                cvss3_severity_level = None
            try:
                cvss2_severity_level = Cvss2.objects.values_list(
                    "cvss2_severity_level", flat=True
                ).get(cvss2_severity_code=severity)
            except Cvss2.DoesNotExist:
                cvss2_severity_level = None
            if cvss3_severity_level is not None and cvss2_severity_level is not None:
                cve_id_queryset = cve_id_queryset.filter(
                    Q(cvss3__cvss3_severity_level__gte=cvss3_severity_level)
                    | Q(cvss2__cvss2_severity_level__gte=cvss2_severity_level)
                )
            elif cvss3_severity_level is not None:
                cve_id_queryset = cve_id_queryset.filter(
                    cvss3__cvss3_severity_level__gte=cvss3_severity_level
                )
            elif cvss2_severity_level is not None:
                cve_id_queryset = cve_id_queryset.filter(
                    cvss2__cvss2_severity_level__gte=cvss2_severity_level
                )
        if year:
            cve_id_queryset = cve_id_queryset.filter(cve_year__gte=year)
        if keyword and not (user_id and enable_user_keyword):
            cve_id_queryset = cve_id_queryset.filter(
                cve_full_text_search__cve_text_for_search__search=keyword
            )
        if user_id:
            if labels:
                # ※ 注意
                # cve_id_queryset = cve_id_queryset.filter(
                #    user_cve_label__cve_label__cve_label_id__in=labels
                # ).filter(user_cve_label__user__id=user_id)
                #
                # 上記のようにfilterをチェーンする書き方をすると以下のバグを踏んでしまい
                # 意図したSQLにならない。
                #
                # https://code.djangoproject.com/ticket/29196
                cve_id_queryset = cve_id_queryset.filter(
                    user_cve_label__cve_label__cve_label_id__in=labels,
                    user_cve_label__user__id=user_id,
                )

            if enable_user_keyword:
                keyword_list = list(
                    UserKeyword.objects.values_list("keyword", flat=True).filter(
                        user_id=user_id
                    )
                )
                if keyword:
                    keyword_list.append(keyword)
                cve_id_queryset = cve_id_queryset.filter(
                    cve_full_text_search__cve_text_for_search__search=" ".join(
                        keyword_list
                    )
                )

        total_count = cve_id_queryset.count()
        cve_id_queryset = cve_id_queryset.order_by("-cve_id")
        offset = display_count_per_page * (page - 1)
        cve_id_queryset = cve_id_queryset[offset : offset + display_count_per_page]
        cve_id_list = list(cve_id_queryset)
        cve_id_label_dict = {}
        cve_id_comment_dict = {}
        if user_id:
            label_queryset = (
                UserCveLabel.objects.select_related("cve")
                .filter(user_id=user_id)
                .filter(cve_id__in=cve_id_list)
            )
            cve_id_label_dict = {r.cve.cve_id: r.cve_label_id for r in label_queryset}
            comment_queryset = (
                UserCveComment.objects.select_related("cve")
                .filter(user_id=user_id)
                .filter(cve_id__in=cve_id_list)
            )
            cve_id_comment_dict = {
                r.cve.cve_id: r.cve_comment for r in comment_queryset
            }
        cve_list_queryset = (
            Cve.objects.filter(cve_id__in=cve_id_list)
            .select_related("cvss3")
            .select_related("cvss2")
            .order_by("-cve_id")
        )
        cve_list = []
        for cve in cve_list_queryset:
            cve_list.append(
                CveRecord(
                    cve_id=cve.cve_id,
                    cve_url=cve.cve_url,
                    nvd_url=cve.nvd_url,
                    nvd_content_exists=cve.nvd_content_exists,
                    cve_description=cve.cve_description,
                    cvss3_score=cve.cvss3_score,
                    cvss3_severity=cve.cvss3.cvss3_severity_code
                    if cve.cvss3 is not None
                    else None,
                    cvss2_score=cve.cvss2_score,
                    cvss2_severity=cve.cvss2.cvss2_severity_code
                    if cve.cvss2 is not None
                    else None,
                    published_date=cve.published_date,
                    label_id=cve_id_label_dict.get(cve.cve_id),
                    comment=cve_id_comment_dict.get(cve.cve_id),
                )
            )
        display_count_from = display_count_per_page * (page - 1) + 1 if cve_list else 0
        display_count_to = display_count_per_page * (page - 1) + len(cve_list)
        max_page = int((total_count - 1) / display_count_per_page) + 1
        return CveListResult(
            total_count=total_count,
            display_count_from=display_count_from,
            display_count_to=display_count_to,
            current_page=page,
            max_page=max_page,
            cve_list=cve_list,
        )
