import logging
from dataclasses import asdict

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.response import Response

from api.data import ExpectedErrorAPIResponse, UnexpectedErrorAPIResponse

logger = logging.getLogger(__name__)


def cverooster_exception_handler(exc, context):
    if isinstance(exc, APIException):
        logger.info(exc, exc_info=True)
        code = str(exc.get_codes())
        error_messages = []
        if isinstance(exc.detail, str):
            error_messages = [exc.detail]
        elif isinstance(exc.detail, dict):
            error_messages = list(exc.detail.values())
        elif isinstance(exc.detail, list):
            error_messages = exc.detail
        response = Response(
            asdict(
                ExpectedErrorAPIResponse(
                    code=code, error_messages=error_messages, result={}
                )
            ),
            status=exc.status_code,
        )
    else:
        logger.exception(exc)
        response = Response(
            asdict(
                UnexpectedErrorAPIResponse(
                    code="internal_server_error",
                    error_messages=["Internal server error occurred."],
                    result={},
                )
            ),
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    return response
