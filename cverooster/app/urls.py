from django.urls import path

from app import views

app_name = "cverooster_app"
urlpatterns = [
    path("healthcheck/", views.HealthCheckView.as_view(), name="healthcheck"),
    path("detail/<str:cve_id>", views.CveDetailView.as_view(), name="cve_detail"),
    path("list/", views.CveListView.as_view(), name="cve_list"),
    path(
        "mypage/keyword_list",
        views.UserKeywordList.as_view(),
        name="user_keyword_list",
    ),
    path("mypage/settings", views.UserSettings.as_view(), name="user_settings",),
    path("account/signup", views.SignupView.as_view(), name="signup",),
    path("account/login", views.CustomLoginView.as_view(), name="login",),
    path("account/logout", views.CustomLogoutView.as_view(), name="logout"),
]
