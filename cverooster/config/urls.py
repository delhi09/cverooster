"""cverooster_api URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path("api/", include("api.urls")),
    path("", include("app.urls")),
]
# 「settings.DEBUG」で判定するとユニットテスト実行時に以下のエラーが発生するので、
# 「settings.DEBUG」ではなく「"debug_toolbar" in settings.INSTALLED_APPS」で
# 判定する。 ※ silkの場合も同様
#
# [発生するエラー]
# django.urls.exceptions.NoReverseMatch: 'djdt' is not a registered namespace
#
# Djangoのユニットテストの仕様で、settings.DEBUGをFalseでオーバーライドすることが原因である。
#
# 詳細は以下を参照
# https://github.com/jazzband/django-silk/issues/74#issuecomment-407154467
# https://docs.djangoproject.com/en/3.0/topics/testing/overview/#other-test-conditions
if "debug_toolbar" in settings.INSTALLED_APPS:
    import debug_toolbar

    urlpatterns.append(path("__debug__/", include(debug_toolbar.urls)))
if "silk" in settings.INSTALLED_APPS:
    urlpatterns.append(path("silk/", include("silk.urls", namespace="silk")))
