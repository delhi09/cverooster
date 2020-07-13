from dataclasses import asdict

from django.db import transaction
from django.utils import timezone
from rest_framework import status, views
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api.data import OKAPIResponse
from api.exceptions import ResourceNotFound
from api.serializers import (
    CveListAPIRequestSerializer,
    DeleteUserCveCommentAPIRequestSerializer,
    DeleteUserCveLabelAPIRequestSerializer,
    SaveUserCveCommentAPIRequestSerializer,
    SaveUserCveLabelAPIRequestSerializer,
    SaveUserKeywordAPIRequestSerializer,
)
from api.services import CveListAPIService
from core.models import Cve, CveLabel, UserCveComment, UserCveLabel, UserKeyword


class CveListAPIView(views.APIView):
    def get(self, request, *args, **kwargs):
        request_serializer = CveListAPIRequestSerializer(data=request.query_params)
        request_serializer.is_valid(raise_exception=True)
        severity = request_serializer.validated_data.get("severity")
        year = request_serializer.validated_data.get("year")
        page = request_serializer.validated_data.get("page", 1)
        keyword = request_serializer.validated_data.get("keyword")
        enable_user_keyword = request_serializer.validated_data.get(
            "enable_user_keyword"
        )
        labels = request_serializer.validated_data.get("label")
        service = CveListAPIService()

        result = None
        if request.user.is_anonymous:
            result = service.find_cve_list(
                severity=severity,
                year=year,
                keyword=keyword,
                page=page,
                display_count_per_page=10,
            )
        else:
            result = service.find_cve_list(
                severity=severity,
                year=year,
                keyword=keyword,
                page=page,
                display_count_per_page=10,
                user_id=request.user.id,
                labels=labels,
                enable_user_keyword=enable_user_keyword,
            )
        response_body = OKAPIResponse(code="ok", error_messages=[], result=result)
        return Response(asdict(response_body), status.HTTP_200_OK)


class SaveUserKeywordAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request_serializer = SaveUserKeywordAPIRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        keyword = request_serializer.validated_data.get("keyword")
        if (
            UserKeyword.objects.filter(user__id=request.user.id)
            .filter(keyword=keyword)
            .exists()
        ):
            return Response("リソースが既に存在します。", status.HTTP_204_NO_CONTENT)
        count_keyword = UserKeyword.objects.filter(user__id=request.user.id).count()
        if count_keyword >= 50:
            return Response("登録できるキーワードの上限を超過しています。", status.HTTP_400_BAD_REQUEST)
        current_timestamp = timezone.localtime(timezone.now())
        model = UserKeyword(
            id=None,
            user=request.user,
            keyword=keyword,
            created_by="SaveUserKeywordAPI",
            created_at=current_timestamp,
            updated_by="SaveUserKeywordAPI",
            updated_at=current_timestamp,
        )
        model.save()
        response_body = OKAPIResponse(
            code="ok", error_messages=[], result={"status": "completed"}
        )
        return Response(asdict(response_body), status.HTTP_200_OK)


class DeleteUserKeywordAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        request_serializer = SaveUserKeywordAPIRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        keyword = request_serializer.validated_data.get("keyword")
        model = UserKeyword.objects.filter(user__id=request.user.id).filter(
            keyword=keyword
        )
        if not model:
            return Response("削除対象のリソースが存在しません。", status.HTTP_404_NOT_FOUND)
        model.delete()
        response_body = OKAPIResponse(
            code="ok", error_messages=[], result={"status": "completed"}
        )
        return Response(asdict(response_body), status.HTTP_200_OK)


class SaveUserCveCommentAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        request_serializer = SaveUserCveCommentAPIRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        cve_id = request_serializer.validated_data.get("cve_id")
        comment = request_serializer.validated_data.get("comment")
        model = UserCveComment.objects.filter(
            user__id=request.user.id, cve__cve_id=cve_id
        ).first()
        current_timestamp = timezone.localtime(timezone.now())
        if model:
            model.cve_comment = comment
            model.updated_by = "SaveUserCveCommentAPIView"
            model.updated_at = current_timestamp
            model.save()
            response_body = OKAPIResponse(
                code="ok", error_messages=[], result={"status": "completed"}
            )
            return Response(asdict(response_body), status.HTTP_200_OK)
        cve = Cve.objects.filter(cve_id=cve_id).first()
        if cve is None:
            raise ResourceNotFound(f"cve.cve_id={cve_id}")

        model = UserCveComment(
            user=request.user,
            cve=cve,
            cve_comment=comment,
            created_by="SaveUserCveCommentAPIView",
            created_at=current_timestamp,
            updated_by="SaveUserCveCommentAPIView",
            updated_at=current_timestamp,
        )
        model.save()
        response_body = OKAPIResponse(
            code="ok", error_messages=[], result={"status": "completed"}
        )
        return Response(asdict(response_body), status.HTTP_200_OK)


class DeleteUserCveCommentAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        request_serializer = DeleteUserCveCommentAPIRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        cve_id = request_serializer.validated_data.get("cve_id")
        model = UserCveComment.objects.filter(
            user__id=request.user.id, cve__cve_id=cve_id
        ).first()
        if not model:
            raise ResourceNotFound(f"cve.cve_id={cve_id}")
        model.delete()
        response_body = OKAPIResponse(
            code="ok", error_messages=[], result={"status": "completed"}
        )
        return Response(asdict(response_body), status.HTTP_200_OK)


class SaveUserCveLabelAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        request_serializer = SaveUserCveLabelAPIRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        cve_id = request_serializer.validated_data.get("cve_id")
        label = request_serializer.validated_data.get("label")
        model = UserCveLabel.objects.filter(
            user__id=request.user.id, cve__cve_id=cve_id
        ).first()
        if model:
            model.delete()
        cve = Cve.objects.filter(cve_id=cve_id).first()
        if cve is None:
            raise ResourceNotFound(f"cve.cve_id={cve_id}")
        cve_label = CveLabel.objects.filter(cve_label_id=label).first()
        if cve_label is None:
            raise ResourceNotFound(f"cve_label.cve_label_id={label}")
        current_timestamp = timezone.localtime(timezone.now())
        model = UserCveLabel(
            user=request.user,
            cve=cve,
            cve_label=cve_label,
            created_by="SaveUserCveLabelAPIView",
            created_at=current_timestamp,
            updated_by="SaveUserCveLabelAPIView",
            updated_at=current_timestamp,
        )
        model.save()
        response_body = OKAPIResponse(
            code="ok", error_messages=[], result={"status": "completed"}
        )
        return Response(asdict(response_body), status.HTTP_200_OK)


class DeleteUserCveLabelAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        request_serializer = DeleteUserCveLabelAPIRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        cve_id = request_serializer.validated_data.get("cve_id")
        user_cve_labels = UserCveLabel.objects.filter(
            user__id=request.user.id, cve__cve_id=cve_id
        )
        if not user_cve_labels:
            raise ResourceNotFound(f"cve.cve_id={cve_id}")
        user_cve_labels.delete()
        response_body = OKAPIResponse(
            code="ok", error_messages=[], result={"status": "completed"}
        )
        return Response(asdict(response_body), status.HTTP_200_OK)
