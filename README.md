# Link Validator

Paste a batch of links and check each one at once. Every link is opened and its
real content is inspected, then sorted into:

- **File found** — the link actually serves a real file. Detected by the file's
  own signature (magic bytes): JPG, PNG, GIF, WEBP, BMP, TIFF, SVG, HEIC, PDF,
  DOC/DOCX, XLS/XLSX, PPT/PPTX, ZIP, RAR, 7z, GZ, MP4, MP3, WAV, and more.
- **Blank** — no real file: an empty response, a 404 / error, a dead or
  unreachable host, or an HTML web page returned instead of a file — even when
  the URL ends in `.jpg`.

The extension and the HTTP status alone are never trusted; the actual bytes decide.
Checks run on the server, so cross-origin (CORS) blocking does not apply.
Results stream in live and redirects are followed to the final URL.

## Run locally

```bash
pip install -r requirements.txt
python main.py
# open http://localhost:8000
```

## Deploy on Railway

1. Push this folder to a GitHub repo.
2. Railway: New Project → Deploy from GitHub repo → pick the repo.
3. Railway auto-detects Python and uses the `Procfile` start command.
   No env vars needed; `$PORT` is provided by Railway.

## Notes

- Up to 500 links per request, 20 checked in parallel, 15s timeout each.
- Only the first 4 KB of each link is downloaded to identify it, so large files
  are not fully fetched.
- Plain-text responses (`.txt`, `.md`, raw text) are treated as **Blank** (no
  file). If you want those counted as files, ask and it's a one-line change.
- A "not available" placeholder image is still a real image file, so it will
  show as **File found**. True blanks (empty, 404, web page) are caught.
