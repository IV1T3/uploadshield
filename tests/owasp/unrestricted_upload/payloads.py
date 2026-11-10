"""Payloads and helpers for the Unrestricted File Upload tests."""

from __future__ import annotations

import gzip
import struct
import zlib

from tests.support import corpus
from tests.support.harness import App, Reply, file

PNG = corpus.png()
JSP_SHELL = (
    b'<%@ page import="java.io.*" %><% Runtime.getRuntime().exec(request.getParameter("c")); %>'
)
ASP_SHELL = b'<%@ Language=VBScript %><% CreateObject("WScript.Shell").Run(Request("c")) %>'
RAR = b"Rar!\x1a\x07\x01\x00" + b"\x00" * 64
SEVEN_ZIP = b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64
GZIP = gzip.compress(b"hello")
SWF = b"FWS\x0a" + struct.pack("<I", 64) + b"\x00" * 56  # Flash, uncompressed
SWF_COMPRESSED = b"CWS\x0a" + struct.pack("<I", 64) + zlib.compress(b"\x00" * 56)
XAP = corpus.build_zip({"AppManifest.xaml": b"<Deployment/>", "App.dll": b"MZ"})  # Silverlight
CROSSDOMAIN_XML = (
    b'<?xml version="1.0"?><cross-domain-policy>'
    b'<allow-access-from domain="*"/></cross-domain-policy>'
)


def blocked(app: App, name: str, data: bytes = PNG, path: str = "/legacy") -> Reply:
    """The upload never reaches the view: refused, or dropped by the framework itself.

    Django's parser removes path components and unprintable characters from names and
    drops parts whose name ends up empty; what remains is then checked like any name.
    """
    reply = app.post(path, file(name, data))
    if reply.status == 200:
        assert reply.files == [], (app.name, name, reply.files)
    elif reply.status != 422:  # FastAPI: a dropped part leaves a required field missing
        assert reply.status in (400, 413, 415), (app.name, name, reply.status)
        assert reply.rejection is not None
    return reply
