"""A minimal FastAPI upload app protected by uploadshield.

Run:  uv run --with uvicorn uvicorn examples.fastapi_app:app --port 8812
"""

import hashlib
from typing import Annotated

from fastapi import Depends, FastAPI, UploadFile

from uploadshield.fastapi import UploadShield

shield = UploadShield()
# App-wide safety net: every multipart request is checked against DEFAULT_POLICY.
app = FastAPI(dependencies=[Depends(shield.all_files())])


async def summary(field: str, *uploads: UploadFile) -> dict[str, object]:
    files = []
    for upload in uploads:
        data = await upload.read()
        files.append(
            {
                "field": field,
                "name": upload.filename,
                "content_type": upload.content_type,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return {"files": files}


@app.post("/documents")
async def documents(
    file: Annotated[UploadFile, Depends(shield.file("documents"))],
) -> dict[str, object]:
    return await summary("file", file)


@app.post("/avatar")
async def avatar(
    file: Annotated[UploadFile, Depends(shield.file("sanitized_images"))],
) -> dict[str, object]:
    return await summary("file", file)  # re-encoded, metadata stripped, random name


@app.post("/gallery")
async def gallery(
    files: Annotated[list[UploadFile], Depends(shield.files("images"))],
) -> dict[str, object]:
    return await summary("files", *files)


@app.post("/legacy")
async def legacy(file: UploadFile) -> dict[str, object]:  # protected app-wide
    return await summary("file", file)
