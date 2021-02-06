from datetime import date
import re

from rest_framework import serializers

from api.constants import REGEX_PATERN_CVE_ID, REGEX_PATERN_KEYWORD


class CveListAPIRequestSerializer(serializers.Serializer):
    severity = serializers.CharField(required=False)
    year = serializers.IntegerField(required=False)
    page = serializers.IntegerField(required=False)
    keyword = serializers.CharField(required=False)
    label = serializers.ListField(
        required=False, child=serializers.IntegerField(required=False)
    )
    enable_user_keyword = serializers.BooleanField(required=False, default=False)

    def validate_severity(self, value):
        severity_list = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        if value not in severity_list:
            raise serializers.ValidationError("存在しないseverityを指定しています。")
        return value

    def validate_year(self, value):
        year_min = 1995
        year_max = date.today().year
        if not year_min <= value <= year_max:
            raise serializers.ValidationError("CVEが存在しない年を指定しています。")
        return value

    def validate_page(self, value):
        page_min = 1
        page_max = 100000
        if not page_min <= value <= page_max:
            raise serializers.ValidationError("存在しないページを指定しています。")
        return value

    def validate_keyword(self, value):
        pattern = REGEX_PATERN_KEYWORD
        if not re.match(pattern, value):
            raise serializers.ValidationError("キーワードは半角英数かつ32文字以内で指定してください。")
        return value

    def validate_label(self, list_value):
        label_list = (1, 2, 3, 4)
        for label in list_value:
            if label not in label_list:
                raise serializers.ValidationError("存在しないlabelを指定しています。")
        return list_value


class SaveUserKeywordAPIRequestSerializer(serializers.Serializer):
    keyword = serializers.CharField(required=True)

    def validate_keyword(self, value):
        pattern = REGEX_PATERN_KEYWORD
        if not re.match(pattern, value):
            raise serializers.ValidationError("キーワードは半角英数かつ32文字以内で指定してください。")
        return value


class DeleteUserKeywordAPIRequestSerializer(serializers.Serializer):
    keyword = serializers.CharField(required=True)

    def validate_keyword(self, value):
        pattern = REGEX_PATERN_KEYWORD
        if not re.match(pattern, value):
            raise serializers.ValidationError("キーワードは半角英数かつ32文字以内で指定してください。")
        return value


class SaveUserCveCommentAPIRequestSerializer(serializers.Serializer):
    cve_id = serializers.CharField(required=True)
    comment = serializers.CharField(required=True)

    def validate_cve_id(self, value):
        if not re.match(REGEX_PATERN_CVE_ID, value):
            raise serializers.ValidationError("CVE_IDのフォーマットが不正です。")
        return value

    def validate_comment(self, value):
        comment_len_max = 255
        if len(value) > comment_len_max:
            raise serializers.ValidationError("コメントは255文字以内で指定してください。")
        return value


class DeleteUserCveCommentAPIRequestSerializer(serializers.Serializer):
    cve_id = serializers.CharField(required=True)

    def validate_cve_id(self, value):
        if not re.match(REGEX_PATERN_CVE_ID, value):
            raise serializers.ValidationError("CVE_IDのフォーマットが不正です。")
        return value


class SaveUserCveLabelAPIRequestSerializer(serializers.Serializer):
    cve_id = serializers.CharField(required=True)
    label = serializers.IntegerField(required=True)

    def validate_cve_id(self, value):
        if not re.match(REGEX_PATERN_CVE_ID, value):
            raise serializers.ValidationError("CVE_IDのフォーマットが不正です。")
        return value

    def validate_label(self, value):
        label_list = (1, 2, 3, 4)
        if value not in label_list:
            raise serializers.ValidationError("存在しないlabelを指定しています。")
        return value


class DeleteUserCveLabelAPIRequestSerializer(serializers.Serializer):
    cve_id = serializers.CharField(required=True)

    def validate_cve_id(self, value):
        if not re.match(REGEX_PATERN_CVE_ID, value):
            raise serializers.ValidationError("CVE_IDのフォーマットが不正です。")
        return value
