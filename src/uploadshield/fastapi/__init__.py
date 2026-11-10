"""FastAPI integration: validated uploads as dependencies.

::

    from fastapi import Depends, FastAPI, UploadFile
    from uploadshield.fastapi import UploadShield

    shield = UploadShield()
    app = FastAPI(dependencies=[Depends(shield.all_files())])  # optional safety net

    @app.post("/avatar")
    async def avatar(file: Annotated[UploadFile, Depends(shield.file("sanitized_images"))]):
        ...  # `file` is validated and sanitized; its content type comes from its bytes

FastAPI parses the request body before dependencies run, so files are checked once
they have been received (there is no per-file streaming hook as in Django).  Limit
request sizes at the server or proxy.  Validation runs in Starlette's thread pool, so
the event loop is never blocked.
"""

from .shield import UploadShield

__all__ = ["UploadShield"]
