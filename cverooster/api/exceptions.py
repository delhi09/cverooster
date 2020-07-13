from rest_framework import status
from rest_framework.exceptions import APIException


class ResourceNotFound(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "reource not found.[{resource_name}]"
    default_code = "resource_not_found"

    def __init__(self, resource_name, detail=None, code=None):
        if detail is None:
            detail = self.default_detail.format(resource_name=resource_name)
        super().__init__(detail, code)
