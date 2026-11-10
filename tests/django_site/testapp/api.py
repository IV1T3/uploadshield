"""DRF endpoints (only imported when djangorestframework is installed)."""

from __future__ import annotations

from typing import Any

from django.utils.decorators import method_decorator
from rest_framework import serializers
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    parser_classes,
    permission_classes,
)
from rest_framework.parsers import FileUploadParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from uploadshield.django import get_upload_validation, validate_uploads


def summary(request: Any) -> dict[str, Any]:
    files = request.FILES  # DRF's FileUploadParser returns a plain dict
    validation = get_upload_validation(request)
    names = {k: files.getlist(k) if hasattr(files, "getlist") else [files[k]] for k in files}
    return {
        "files": {k: [f.name for f in v] for k, v in names.items()},
        "validated": validation is not None,
    }


@validate_uploads("pdf")
class DocumentAPI(APIView):
    parser_classes = (MultiPartParser,)
    authentication_classes = ()
    permission_classes = ()

    def post(self, request: Any) -> Response:
        return Response(summary(request))

    def put(self, request: Any) -> Response:
        return Response(summary(request))


@validate_uploads("pdf")
class RawUploadAPI(APIView):
    parser_classes = (FileUploadParser,)
    authentication_classes = ()
    permission_classes = ()

    def put(self, request: Any, filename: str) -> Response:
        return Response(summary(request))


@api_view(["POST", "PUT"])
@authentication_classes([])
@permission_classes([])
@parser_classes([MultiPartParser])
@validate_uploads("pdf")
def document_function(request: Any) -> Response:
    """``@api_view`` wraps the view: routing sees DRF's wrapper, not this decorator."""
    return Response(summary(request))


class MethodDecoratedAPI(APIView):
    parser_classes = (MultiPartParser,)
    authentication_classes = ()
    permission_classes = ()

    @method_decorator(validate_uploads("pdf"))
    def post(self, request: Any) -> Response:
        return Response(summary(request))


@validate_uploads(None, fields={"file": "pdf"})
class RawFieldAPI(APIView):
    """A raw body is ``request.FILES["file"]``: the per-field policy must apply to it."""

    parser_classes = (FileUploadParser,)
    authentication_classes = ()
    permission_classes = ()

    def put(self, request: Any, filename: str) -> Response:
        return Response(summary(request))


class AttachmentsSerializer(serializers.Serializer):
    attachments = serializers.ListField(child=serializers.FileField())


@validate_uploads(None, fields={"attachments": "pdf"})
class AttachmentsAPI(APIView):
    """DRF's ListField also reads "attachments[0]" and "attachments.0"."""

    parser_classes = (MultiPartParser,)
    authentication_classes = ()
    permission_classes = ()

    def post(self, request: Any) -> Response:
        serializer = AttachmentsSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"errors": serializer.errors}, status=400)
        return Response({"stored": [f.name for f in serializer.validated_data["attachments"]]})


class DocumentSerializer(serializers.Serializer):
    file = serializers.FileField()


@validate_uploads("pdf", on_reject="field")
class SerializerAPI(APIView):
    parser_classes = (MultiPartParser,)
    authentication_classes = ()
    permission_classes = ()

    def post(self, request: Any) -> Response:
        serializer = DocumentSerializer(data=request.data)
        serializer.is_valid()
        return Response({"errors": serializer.errors})
