import re
from dataclasses import asdict

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.messages.views import SuccessMessageMixin
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.generic import CreateView

from app.data import UserSettingsSaveData
from app.forms import SignupForm, UserSettingsForm
from app.services import (
    CveDetailService,
    CveListService,
    UserKeywordListService,
    UserSettingsViewService,
)


def csrf_failure(request, reason=""):
    """CSRF認証失敗時に呼ばれる関数ビュー
    
    Djangoの仕様により、403.htmlを配置していても、CSRF認証失敗時には
    Djangoの組み込みの別のエラー画面が表示される。

    本アプリケーションではCSRF認証失敗時も独自の403.htmlを表示させたいため、
    公式ドキュメントに従い「csrf_failure」という関数ビューを定義する。

    詳細は以下を参照。
    https://docs.djangoproject.com/en/3.0/ref/settings/#csrf-failure-view
    https://stackoverflow.com/questions/31981239/django-custom-403-template

    """
    return render(request, "403.html")


class HealthCheckView(View):
    """AWSのALBのヘルスチェック用のURL"""

    def get(self, request, *args, **kwargs):
        return HttpResponse("ok")


class CveDetailView(View):
    def get(self, request, *args, **kwargs):
        cve_id = kwargs["cve_id"]
        if not re.match(r"^CVE-([0-9]{4})-([0-9]{4,})$", cve_id):
            return render(request, "detail.html", {"aaa": "bbb"})
        service = CveDetailService()
        context = service.create_cve_detail_view_context(cve_id)
        return render(request, "detail.html", {"context": asdict(context)})


class CveListView(View):
    def get(self, request, *args, **kwargs):
        service = CveListService()
        user_id = request.user.id if not request.user.is_anonymous else None
        context = service.create_cve_list_view_context(user_id)
        return render(request, "list.html", {"context": asdict(context)})


class UserKeywordList(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        service = UserKeywordListService()
        context = service.create_user_keyword_list_context(request.user.id)
        return render(request, "user_keyword_list.html", {"context": asdict(context)})


class UserSettings(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        service = UserSettingsViewService()
        context = service.create_user_settings_context(request.user.id)
        return render(request, "user_settings.html", {"context": context})

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        service = UserSettingsViewService()
        context = service.create_user_settings_context(request.user.id)
        form = UserSettingsForm(request.POST)
        context.form = form
        if not form.is_valid():
            severity_code = request.POST.get("severity")
            year = int(request.POST.get("year")) if request.POST.get("year") else None
            label_id_list = []
            if request.POST.getlist("label") and "ALL" not in request.POST.getlist(
                "label"
            ):
                for label_id in request.POST.getlist("label"):
                    if label_id.isnumeric():
                        label_id_list.append(int(label_id))
            enable_user_keyword = (
                str(True).lower()
                == str(request.POST.get("enable_user_keyword")).lower()
            )
            mail_address = request.POST.get("mail_address")
            notify_mail = (
                str(True).lower() == str(request.POST.get("notify_mail")).lower()
            )
            slack_webhook_url = request.POST.get("slack_webhook_url")
            notify_slack = (
                str(True).lower() == str(request.POST.get("notify_slack")).lower()
            )
            save_data = UserSettingsSaveData(
                severity_code=severity_code,
                year=year,
                label_id_list=label_id_list,
                enable_user_keyword=enable_user_keyword,
                mail_address=mail_address,
                notify_mail=notify_mail,
                slack_webhook_url=slack_webhook_url,
                notify_slack=notify_slack,
            )
            context.user_settings_save_data = save_data
            return render(request, "user_settings.html", {"context": context})
        severity_code = form.cleaned_data["severity"]
        year = form.cleaned_data["year"]
        label_id_list = []
        if form.cleaned_data["label"] and "ALL" not in form.cleaned_data["label"]:
            label_id_list = [int(label_id) for label_id in form.cleaned_data["label"]]
        enable_user_keyword = (
            str(True).lower() == str(form.cleaned_data["enable_user_keyword"]).lower()
        )
        mail_address = form.cleaned_data["mail_address"]
        notify_mail = str(True).lower() == str(form.cleaned_data["notify_mail"]).lower()
        slack_webhook_url = form.cleaned_data["slack_webhook_url"]
        notify_slack = (
            str(True).lower() == str(form.cleaned_data["notify_slack"]).lower()
        )
        save_data = UserSettingsSaveData(
            severity_code=severity_code,
            year=year,
            label_id_list=label_id_list,
            enable_user_keyword=enable_user_keyword,
            mail_address=mail_address,
            notify_mail=notify_mail,
            slack_webhook_url=slack_webhook_url,
            notify_slack=notify_slack,
        )
        service.save_user_settings(request.user.id, save_data)
        messages.info(request, "設定を更新しました。")
        return redirect("cverooster_app:cve_list")


class SignupView(SuccessMessageMixin, CreateView):
    form_class = SignupForm
    success_url = reverse_lazy("cverooster_app:cve_list")
    template_name = "registration/signup.html"
    success_message = "会員登録に成功しました。ログインしました。"

    def form_valid(self, form):
        valid = super().form_valid(form)
        login(self.request, self.object)
        return valid


class CustomLoginView(SuccessMessageMixin, LoginView):
    success_message = "ログインしました。"


class CustomLogoutView(LogoutView):
    """Djangoのの組み込みのLogoutViewを継承したクラス

    ログアウト完了後にメッセージフレームワークでログアウト完了のメッセージを
    出力するために、dispatchメソッドをオーバーライドする必要があった。

    (参考)
    https://github.com/django/django/blob/master/django/contrib/auth/views.py#L107
    """

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        auth_logout(request)
        messages.info(request, "ログアウトしました。")
        next_page = self.get_next_page()
        if next_page:
            # Redirect to this page until the session has been cleared.
            return HttpResponseRedirect(next_page)
        return super().dispatch(request, *args, **kwargs)
