import re
from datetime import date
from distutils.util import strtobool

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.forms import ValidationError

from core.models import AppUser


class UserSettingsForm(forms.Form):
    severity = forms.CharField(required=False)
    year = forms.IntegerField(required=False)
    label = forms.MultipleChoiceField(
        choices=(("ALL", "全て"), ("1", "要対応"), ("2", "対応不要"), ("3", "対応済み"),),
        error_messages={"invalid": "存在しないlabelを指定しています。"},
        required=False,
    )
    enable_user_keyword = forms.ChoiceField(
        choices=(("true", "ON"), ("false", "OFF")), required=True
    )
    mail_address = forms.EmailField(
        required=False, error_messages={"invalid": "メールアドレスのフォーマットが不正です。"}
    )
    notify_mail = forms.ChoiceField(
        choices=(("true", "ON"), ("false", "OFF")), required=True
    )
    slack_webhook_url = forms.URLField(
        required=False, error_messages={"invalid": "URLのフォーマットが不正です。"}
    )
    notify_slack = forms.ChoiceField(
        choices=(("true", "ON"), ("false", "OFF")), required=True
    )

    def clean_severity(self):
        severity = self.cleaned_data["severity"]
        if not severity:
            return severity
        valid_severity_list = ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        if severity not in valid_severity_list:
            raise ValidationError("存在しないseverityを指定しています。", code="invalid")
        return severity

    def clean_year(self):
        year = self.cleaned_data["year"]
        if not year:
            return year
        valid_year_min = 1995
        valid_year_max = date.today().year
        if not valid_year_min <= year <= valid_year_max:
            raise ValidationError("CVEが存在しない年を指定しています。", code="invalid")
        return year

    def clean_slack_webhook_url(self):
        slack_webhook_url = self.cleaned_data["slack_webhook_url"]
        if not slack_webhook_url:
            return slack_webhook_url
        if not re.match(r"^https://hooks.slack.com/services/.+$", slack_webhook_url):
            raise ValidationError("URLのフォーマットが不正です。", code="invalid")
        return slack_webhook_url

    def clean(self):
        mail_address = self.cleaned_data.get("mail_address")
        notify_mail = self.cleaned_data.get("notify_mail", str(False))
        if strtobool(notify_mail) and not mail_address:
            raise ValidationError("メールアドレスを設定してください。", code="invalid")
        slack_webhook_url = self.cleaned_data.get("slack_webhook_url")
        notify_slack = self.cleaned_data.get("notify_slack", str(False))
        if strtobool(notify_slack) and not slack_webhook_url:
            raise ValidationError("Slack Webhook URLを設定してください。")


class SignupForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = AppUser
