# Link Validator

Paste a batch of links and check each one at once. Every link is sorted into:

- **Website** — a live page (returns HTML)
- **File** — a downloadable file (PDF, image, zip, doc, etc.)
- **Blank** — dead, empty, unreachable, or an error (4xx/5xx, timeout, bad SSL)

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
2. In Railway: New Project → Deploy from GitHub repo → pick the repo.
3. Railway auto-detects Python and uses the `Procfile` start command.
   No env vars needed; `$PORT` is provided by Railway.

## Notes

- Up to 500 links per request, 20 checked in parallel.
- Per-request timeout is 15s.
- `.json`, `.xml`, `.csv`, `.txt` are treated as files; `.html`, `.php`, no-extension pages are treated as websites.
