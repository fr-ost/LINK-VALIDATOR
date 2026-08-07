import asyncio
import json
import os
import re
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="Link Validator")
BASE_DIR = Path(__file__).parent

MAX_LINKS = 500
CONCURRENCY = 20
SNIFF_BYTES = 4096  # bytes read from the start of each link to inspect its content

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "*/*",
}

# Content types that count as a real file, used only as a fallback when the
# magic-byte signature is unknown but the body is clearly not a web page.
FILE_CT_PREFIXES = ("image/", "video/", "audio/", "font/")
FILE_CT_EXACT = {
    "application/pdf", "application/zip", "application/x-zip-compressed",
    "application/octet-stream", "application/gzip", "application/x-gzip",
    "application/x-tar", "application/x-7z-compressed", "application/x-rar-compressed",
    "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/rtf", "application/x-msdownload", "application/vnd.android.package-archive",
    "application/x-apple-diskimage", "application/epub+zip",
}
FILE_CT_CONTAINS = ("vnd.openxmlformats", "vnd.oasis.opendocument",
                    "spreadsheet", "presentation", "wordprocessing")


class CheckRequest(BaseModel):
    urls: list[str] = []


def human_size(n):
    if n is None:
        return ""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def sniff_filetype(b: bytes):
    """Return a file-type label if the bytes match a known signature, else None."""
    if len(b) < 3:
        return None
    # Images
    if b[:3] == b"\xFF\xD8\xFF":
        return "jpg"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if b[:2] == b"BM":
        return "bmp"
    if b[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if b[:4] == b"\x00\x00\x01\x00":
        return "ico"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    if b[4:8] == b"ftyp":
        brand = b[8:12]
        if brand in (b"heic", b"heix", b"hevc", b"mif1", b"heim", b"heis"):
            return "heic"
        if brand == b"avif":
            return "avif"
        return "mp4"
    # Documents / archives
    if b[:4] == b"%PDF":
        return "pdf"
    if b[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip/office"
    if b[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1a\xE1":
        return "doc/xls/ppt"
    if b[:5] == b"{\\rtf":
        return "rtf"
    if b[:4] == b"Rar!":
        return "rar"
    if b[:6] == b"7z\xBC\xAF\x27\x1C":
        return "7z"
    if b[:2] == b"\x1f\x8b":
        return "gz"
    # Audio
    if b[:3] == b"ID3" or b[:2] == b"\xFF\xFB":
        return "mp3"
    if b[:4] == b"OggS":
        return "ogg"
    if b[:4] == b"fLaC":
        return "flac"
    if b[:4] == b"RIFF" and b[8:12] == b"WAVE":
        return "wav"
    return None


def looks_like_svg(b: bytes, content_type: str):
    head = b[:2048].lstrip().lower()
    if b"<svg" in head:
        return True
    if "svg" in content_type.lower() and b"<svg" in b[:4096].lower():
        return True
    return False


def looks_like_html(b: bytes):
    head = b[:1024].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<!--")):
        return True
    if head.startswith(b"<") and b"<html" in head:
        return True
    return False


def content_type_is_file(ct: str):
    ct = ct.split(";")[0].strip().lower()
    if not ct or ct in ("text/html", "application/xhtml+xml"):
        return False
    if any(ct.startswith(p) for p in FILE_CT_PREFIXES):
        return True
    if ct in FILE_CT_EXACT:
        return True
    if any(k in ct for k in FILE_CT_CONTAINS):
        return True
    return False


def normalize(raw):
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        return "https://" + raw
    return raw


async def do_check(client, checked_url, base):
    async with client.stream("GET", checked_url, headers=UA) as resp:
        status = resp.status_code
        ct = resp.headers.get("content-type", "")
        clen = resp.headers.get("content-length")
        final = str(resp.url)

        base.update({
            "http_status": status,
            "content_type": ct.split(";")[0].strip(),
            "final_url": final,
            "size": human_size(clen),
        })

        # A real file link should return 2xx/3xx. Errors mean no file.
        if status >= 400:
            base.update({"category": "blank", "reason": f"HTTP {status}"})
            return base

        # Read only the first bytes; enough to identify the file, cheap for big files.
        body = b""
        async for chunk in resp.aiter_bytes():
            body += chunk
            if len(body) >= SNIFF_BYTES:
                break

        if not body:
            base.update({"category": "blank", "reason": "Empty response"})
            return base

        # 1) Real file signature -> positive.
        ftype = sniff_filetype(body)
        if ftype:
            base.update({"category": "file", "file_type": ftype})
            return base

        # 2) SVG image (text-based, so checked separately) -> positive.
        if looks_like_svg(body, ct):
            base.update({"category": "file", "file_type": "svg"})
            return base

        # 3) A web page / error page in disguise -> no file.
        if looks_like_html(body):
            base.update({"category": "blank", "reason": "No file (web page)"})
            return base

        # 4) Unknown signature but the server clearly serves a binary file.
        if content_type_is_file(ct):
            sub = ct.split("/")[-1].split(";")[0].strip()
            base.update({"category": "file", "file_type": sub or "file"})
            return base

        # Otherwise there is no downloadable file here.
        base.update({"category": "blank", "reason": "No file"})
        return base


async def check_one(client, insecure, raw, index):
    checked = normalize(raw)
    base = {
        "index": index, "url": raw.strip(), "checked_url": checked,
        "category": "blank", "http_status": None, "content_type": "",
        "final_url": "", "size": "", "file_type": "", "reason": "",
    }
    try:
        return await do_check(client, checked, base)
    except httpx.ConnectError as e:
        msg = str(e).lower()
        if "ssl" in msg or "certificate" in msg:
            try:
                return await do_check(insecure, checked, base)
            except Exception:
                base["reason"] = "SSL / certificate error"
                return base
        base["reason"] = "Unreachable"
        return base
    except httpx.ConnectTimeout:
        base["reason"] = "Connection timed out"
        return base
    except httpx.ReadTimeout:
        base["reason"] = "Read timed out"
        return base
    except httpx.TooManyRedirects:
        base["reason"] = "Too many redirects"
        return base
    except (httpx.UnsupportedProtocol, httpx.InvalidURL):
        base["reason"] = "Invalid URL"
        return base
    except Exception as e:
        base["reason"] = type(e).__name__
        return base


async def stream_results(urls):
    timeout = httpx.Timeout(15.0, connect=10.0)
    limits = httpx.Limits(max_connections=CONCURRENCY + 10, max_keepalive_connections=10)
    common = dict(follow_redirects=True, timeout=timeout, limits=limits, headers=UA)

    async with httpx.AsyncClient(verify=True, **common) as client, \
               httpx.AsyncClient(verify=False, **common) as insecure:
        sem = asyncio.Semaphore(CONCURRENCY)

        async def worker(raw, i):
            async with sem:
                return await check_one(client, insecure, raw, i)

        tasks = [asyncio.create_task(worker(u, i)) for i, u in enumerate(urls)]
        for coro in asyncio.as_completed(tasks):
            res = await coro
            yield (json.dumps(res) + "\n").encode()


@app.post("/api/check")
async def api_check(req: CheckRequest):
    seen, urls = set(), []
    for raw in req.urls:
        raw = (raw or "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        urls.append(raw)
        if len(urls) >= MAX_LINKS:
            break

    return StreamingResponse(
        stream_results(urls),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
