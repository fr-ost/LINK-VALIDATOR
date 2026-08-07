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

# ---- Limits -----------------------------------------------------------------
MAX_LINKS = 500          # hard cap per request
CONCURRENCY = 20         # links checked in parallel
HTML_SNIFF_BYTES = 4096  # how much body to read to judge an html page

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "*/*",
}

# Content types that clearly mean "downloadable file", not a viewable page.
FILE_CT_PREFIXES = ("image/", "video/", "audio/", "font/")
FILE_CT_EXACT = {
    "application/pdf", "application/zip", "application/x-zip-compressed",
    "application/octet-stream", "application/gzip", "application/x-gzip",
    "application/x-tar", "application/x-7z-compressed", "application/x-rar-compressed",
    "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/rtf", "application/x-msdownload", "application/vnd.android.package-archive",
    "application/x-apple-diskimage", "application/epub+zip",
}
FILE_CT_CONTAINS = ("vnd.openxmlformats", "vnd.oasis.opendocument", "spreadsheet",
                    "presentation", "wordprocessing")

# URL path extensions that clearly mean "file".
FILE_EXTS = {
    "pdf", "zip", "rar", "7z", "tar", "gz", "tgz", "bz2",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf", "md",
    "png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico", "tiff", "heic",
    "mp4", "mov", "avi", "mkv", "webm", "mp3", "wav", "flac", "ogg", "m4a",
    "exe", "dmg", "apk", "deb", "rpm", "msi", "iso", "bin",
    "json", "xml", "yaml", "yml", "sql", "epub", "mobi",
}
PAGE_EXTS = {"html", "htm", "php", "asp", "aspx", "jsp", "cfm", ""}


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


def path_ext(url):
    path = re.sub(r"[?#].*$", "", url)          # drop query and fragment
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if "." in last:
        return last.rsplit(".", 1)[-1].lower()
    return ""


def is_file(content_type, disposition, ext):
    if "attachment" in disposition:
        return True
    ct = content_type.split(";")[0].strip().lower()
    if ct in FILE_CT_EXACT:
        return True
    if any(ct.startswith(p) for p in FILE_CT_PREFIXES):
        return True
    if any(k in ct for k in FILE_CT_CONTAINS):
        return True
    if ext in FILE_EXTS and ext not in ("json", "xml", "yaml", "yml"):
        return True
    # data formats: only a file if the URL actually ends in that extension
    if ext in ("json", "xml", "yaml", "yml"):
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
        cd = resp.headers.get("content-disposition", "").lower()
        clen = resp.headers.get("content-length")
        final = str(resp.url)
        ext = path_ext(final)

        base.update({
            "http_status": status,
            "content_type": ct.split(";")[0].strip(),
            "final_url": final,
            "size": human_size(clen),
        })

        if status >= 400:
            base.update({"category": "blank", "reason": f"HTTP {status}"})
            return base

        if is_file(ct, cd, ext):
            base.update({"category": "file", "file_type": ext or ct.split("/")[-1]})
            return base

        # Looks like a page. Read a little to catch truly empty responses.
        head = b""
        if "text/html" in ct.lower() or "xhtml" in ct.lower() or ct == "":
            async for chunk in resp.aiter_bytes():
                head += chunk
                if len(head) >= HTML_SNIFF_BYTES:
                    break
            if clen == "0" or (not head.strip() and not ct):
                base.update({"category": "blank", "reason": "Empty response"})
                return base

        base.update({"category": "website"})
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
                out = await do_check(insecure, checked, base)
                if not out.get("reason"):
                    out["reason"] = "Insecure certificate"
                return out
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
    except httpx.UnsupportedProtocol:
        base["reason"] = "Unsupported URL"
        return base
    except httpx.InvalidURL:
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
