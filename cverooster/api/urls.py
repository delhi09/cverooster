from django.urls import path

from . import views

app_name = "cverooster_api"
urlpatterns = [
    path("cve/list", views.CveListAPIView.as_view(), name="cve_list"),
    path(
        "cve/save_user_keyword",
        views.SaveUserKeywordAPIView.as_view(),
        name="save_user_keyword",
    ),
    path(
        "cve/delete_user_keyword",
        views.DeleteUserKeywordAPIView.as_view(),
        name="delete_user_keyword",
    ),
    path(
        "cve/save_user_cve_comment",
        views.SaveUserCveCommentAPIView.as_view(),
        name="save_user_cve_comment",
    ),
    path(
        "cve/delete_user_cve_comment",
        views.DeleteUserCveCommentAPIView.as_view(),
        name="delete_user_cve_comment",
    ),
    path(
        "cve/save_user_cve_label",
        views.SaveUserCveLabelAPIView.as_view(),
        name="save_user_cve_label",
    ),
    path(
        "cve/delete_user_cve_label",
        views.DeleteUserCveLabelAPIView.as_view(),
        name="delete_user_cve_label",
    ),
]
