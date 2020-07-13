from django.db import models


class Search(models.Lookup):
    """MySQLの全文検索用のカスタムLookup

    DjangoはMySQLの全文検索をサポートしていないため、カスタムLookupを作成する。
    詳細は以下参照
    https://docs.djangoproject.com/en/3.0/howto/custom-lookups/
    https://github.com/django/django/blob/master/docs/releases/1.10.txt#L1039
    https://stackoverflow.com/questions/2248743/django-mysql-full-text-search
    """

    lookup_name = "search"

    def as_mysql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        params = lhs_params + rhs_params
        return "MATCH (%s) AGAINST (%s IN BOOLEAN MODE)" % (lhs, rhs), params
