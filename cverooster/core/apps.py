from django.apps import AppConfig
from django.db import models

from core.lookups import Search


class CoreConfig(AppConfig):
    name = "core"

    def ready(self):
        """MySQLの全文検索用のカスタムLookupを登録する。

        DjangoはMySQLの全文検索をサポートしていないため、カスタムLookupを作成する。
        詳細は以下参照
        https://docs.djangoproject.com/en/3.0/howto/custom-lookups/
        https://github.com/django/django/blob/master/docs/releases/1.10.txt#L1039
        https://stackoverflow.com/questions/2248743/django-mysql-full-text-search
        """
        models.CharField.register_lookup(Search)
        models.TextField.register_lookup(Search)
