import os
import uuid
import mimetypes

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

def _sniff_mime(head_bytes, filename):
    if magic:
        try:
            return magic.from_buffer(head_bytes, mime=True)
        except Exception:
            pass
    # fallback: use uploaded filename's extension
    guess, _ = mimetypes.guess_type(filename)
    return guess or "application/octet-stream"

def _is_path_traversal(filename: str) -> bool:
    # Reject if contains path separators or parent refs
    if "/" in filename or "\\" in filename:
        return True
    if ".." in filename:
        return True
    # get_valid_filename strips problematic chars; if it changes name significantly, reject
    safe = get_valid_filename(filename)
    if not safe or safe != filename:
        return True
    return False

def upload_view(request):
    if request.method == "POST":
        if "file" not in request.FILES:
            return HttpResponseBadRequest("No file uploaded.")

        f = request.FILES["file"]

        # 1) Size check
        if f.size > MAX_BYTES:
            return HttpResponseBadRequest(f"File too large. Max allowed is {MAX_BYTES} bytes.")

        # 2) Path traversal check (client filename should not be trusted)
        client_name = f.name
        if _is_path_traversal(client_name):
            return HttpResponseBadRequest("Invalid filename (possible path traversal).")

        # 3) Mime/content-type sniffing (read head)
        head = f.read(2048)
        sniffed = _sniff_mime(head, client_name)
        # reset file pointer so we can save full content
        f.seek(0)

        if sniffed not in ALLOWED_MIMES:
            return HttpResponseBadRequest(f"Disallowed MIME type: {sniffed}")

        # Save using a safe generated name (do not use client filename directly)
        ext = os.path.splitext(client_name)[1].lower()
        safe_name = f"uploads/{uuid.uuid4().hex}{ext}"
        saved_path = default_storage.save(safe_name, ContentFile(f.read()))

        return HttpResponse(f"Upload OK. Saved as: {saved_path} (mime={sniffed})")

    # GET: simple form
    return render(request, "simple_uploader/upload.html")