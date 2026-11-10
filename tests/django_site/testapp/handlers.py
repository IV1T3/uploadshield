"""Upload handlers and request hooks used to observe ValidatingUploadHandler."""

from __future__ import annotations

from typing import Any

from django.core.files.uploadhandler import MemoryFileUploadHandler, TemporaryFileUploadHandler
from django.http import HttpRequest, HttpResponse

#: Bytes each storage handler actually received, per file name.
STORED: dict[str, int] = {}


class CountingTemporaryHandler(TemporaryFileUploadHandler):
    def new_file(self, *args: Any, **kwargs: Any) -> None:
        super().new_file(*args, **kwargs)
        STORED[self.file_name or ""] = 0

    def receive_data_chunk(self, raw_data: bytes, start: int) -> bytes | None:
        STORED[self.file_name or ""] += len(raw_data)
        return super().receive_data_chunk(raw_data, start)


class ShortCircuitHandler(MemoryFileUploadHandler):
    def handle_raw_input(self, *args: Any, **kwargs: Any) -> Any:
        from django.http import QueryDict
        from django.utils.datastructures import MultiValueDict

        return QueryDict(), MultiValueDict()


class ParseBeforeRouting:
    """Reads request.POST before URL routing, as some third-party apps do."""

    def __init__(self, get_response: Any) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        _ = request.POST
        return self.get_response(request)
