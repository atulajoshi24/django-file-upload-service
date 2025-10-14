import os
import uuid
import mimetypes
import re

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.utils.text import get_valid_filename

# try to import python-magic (libmagic). If not available we fall back.
try:
    import magic
except Exception:
    magic = None

MAX_BYTES = getattr(settings, "MAX_UPLOAD_SIZE", 5 * 1024 * 1024)
ALLOWED_MIMES = getattr(settings, "ALLOWED_MIME_TYPES", ["image/png", "image/jpeg"])
ALLOWED_EXTENSIONS = getattr(settings, "ALLOWED_EXTENSIONS", [".png", ".jpeg"])


def _sniff_mime(head_bytes, filename):
    if magic:
        try:
            return magic.from_buffer(head_bytes, mime=True)
        except Exception:
            pass
    # fallback: use uploaded filename's extension
    guess, _ = mimetypes.guess_type(filename)
    return guess or "application/octet-stream"

def sanitise_filename(filename: str) -> str:
    basename = os.path.basename(os.path.normpath(filename))
    print('basename ->',basename)
    return re.sub(r'[^a-zA-Z0-9._-]', '_', basename) 
    

def upload_file_secure(request):
    print('inside upload_file_secure')
    if request.method == "POST":
        if "file" not in request.FILES:
            return HttpResponseBadRequest("No file uploaded.")

        f = request.FILES["file"]

        # 1) Size check
        if f.size > MAX_BYTES:
            return HttpResponseBadRequest(f"File too large. Max allowed is {MAX_BYTES} bytes.")
        print('file size -> ',f.size)

        # 2) Path traversal check (client filename should not be trusted)
        file_name = f.name
        sanitized_file = sanitise_filename(file_name)
        print('sanitized_file -> ',sanitized_file)

        # 3) Mime/content-type sniffing (read head)
        head = f.read(2048)
        sniffed = _sniff_mime(head, sanitized_file)
        # reset file pointer so we can save full content
        f.seek(0)
        print('sniffed -> ',sniffed)

        if sniffed not in ALLOWED_MIMES:
            return HttpResponseBadRequest(f"Disallowed MIME type: {sniffed}")

        # Save using a safe generated name (do not use client filename directly)
        ext = os.path.splitext(sanitized_file)[1].lower()
        print('ext->',ext)
        if ext not in ALLOWED_EXTENSIONS:
             return HttpResponseBadRequest(f"Disallowed file EXtension: {sniffed}")
        print('ext ->',ext)


        safe_name = f"uploads/{uuid.uuid4().hex}{ext}"
        print('safe_name ->',safe_name)
        saved_path = default_storage.save(safe_name, ContentFile(f.read()))
        print('saved_path ->',saved_path)

        return HttpResponse(f"Upload OK. Saved as: {saved_path} with actual file name : {sanitized_file}(mime={sniffed})")

    # GET: simple form
    return render(request, "simple_uploader/upload.html")


def upload_file(request):
    print('inside upload_file')
    if request.method == "POST":
        if "file" not in request.FILES:
            return HttpResponseBadRequest("No file uploaded.")

        f = request.FILES["file"]

        # 2) Path traversal check (client filename should not be trusted)
        file_name = f.name
        print('inside upload_file')

        # 3) Mime/content-type sniffing (read head)
        head = f.read(2048)
        sniffed = _sniff_mime(head, file_name)
        # reset file pointer so we can save full content
        f.seek(0)
        print('sniffed -> ',sniffed)

        if sniffed not in ALLOWED_MIMES:
            return HttpResponseBadRequest(f"Disallowed MIME type: {sniffed}")

        print('safe_name ->',file_name)
        saved_path = default_storage.save(file_name, ContentFile(f.read()))
        print('saved_path ->',saved_path)

        return HttpResponse(f"Upload OK. Saved as: {saved_path} with actual file name : {file_name} (mime={sniffed})")

    # GET: simple form
    return render(request, "simple_uploader/upload.html")