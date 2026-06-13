#!/usr/bin/python3
"""
FormMap — Embedded Documentation:
'FormMap' is a lightweight multi threaded website auditing tool designed to inspect the structure of one or more web pages and generate reports about internal links, HTML forms, and potentially problematic form implementations. The tool combines `requests` for reliable HTTP retrieval, `BeautifulSoup` for HTML parsing, and a thread pool for concurrent processing of multiple target URLs.
The primary goal is to provide a quick structural audit of websites without requiring a full crawler or browser automation framework. For each supplied URL, the auditor downloads the page, extracts internal links, inventories all forms and their input fields, and flags forms that appear incomplete or suspicious.
Key Features:
Concurrent Scanning:
Multiple websites can be analyzed simultaneously using a `ThreadPoolExecutor`. The maximum number of worker threads is configurable via the `--threads` command-line argument.
Automatic Retry Handling
Each worker thread maintains its own `requests.Session` instance. Sessions are configured with automatic retries for transient server-side failures (HTTP 500, 502, 503, and 504 responses), helping reduce failures caused by temporary network or infrastructure issues.
Internal Link Discovery:
The auditor collects all anchor (`<a>`) elements containing `href` attributes and resolves them to absolute URLs. Only links belonging to the same domain as the scanned page are included in the report.
Form Analysis:
Every HTML form discovered on a page is analyzed and recorded, including:
* Form action URL
* Submission method (GET/POST/etc.)
* Input field metadata
* Missing actions
* Missing inputs
* Anonymous or suspicious input fields
Optional Artifact Storage:
By default, the tool creates an `audit_output/` directory and stores(be careful of overwrites):
* Raw page HTML (`index.html`)
* Internal link maps (`link_map.json`)
* Individual form definitions (`form_*.json`)
This behavior can be disabled using the `--no-save-html` flag.
Flexible Reporting
Results can be displayed directly in the terminal or exported as structured JSON suitable for further processing, integration, or automation.

1. URL Collection
URLs may be supplied directly via:
--urls https://example.com,https://example.org
or loaded from a text file:
--file sites.txt
Each line in the file should contain a single URL.
2. Page Retrieval
For every target URL:
1. A thread-local HTTP session is obtained.
2. The page is downloaded using a configurable timeout.
3. HTTP errors automatically raise exceptions.
4. Retrieved HTML may be saved locally.
If a URL does not include a scheme (`http://` or `https://`), HTTPS is automatically assumed.
Example:
example.com
becomes:
https://example.com
3. Link Extraction:
The downloaded HTML is parsed using BeautifulSoup.
All anchor tags containing `href` attributes are processed:
<a href="/contact">Contact</a>
becomes:
https://example.com/contact
Only links belonging to the same domain are retained.
Duplicate links are automatically removed.
4. Form Inspection
Each HTML form is converted into a structured `FormInfo` object.
Example form:
<form action="/login" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
</form>
Produces:
{
  "action": "https://example.com/login",
  "method": "post",
  "inputs": [
    {
      "name": "username",
      "type": "text"
    },
    {
      "name": "password",
      "type": "password"
    }
  ]
}
5. Broken Form Detection
The auditor attempts to identify common implementation issues.
A form may be flagged if:
* No `action` attribute exists
* No input elements exist
* An input field has no name
* Anonymous text fields are present
Example problematic form:
<form>
    <input type="text">
</form>
Potential findings:
{
  "missing_action": true,
  "missing_inputs": false,
  "suspicious_fields": [
    "missing_input_name",
    "anonymous_input"
  ]
}
Output Directory Structure
A typical output layout looks like:
audit_output/
└── example.com/
    ├── index.html
    ├── link_map.json
    ├── form_1.json
    ├── form_2.json
    └── form_3.json
This allows later inspection without re-downloading the target site.
___Usage Examples___:
Scan a Single Site:
python site_auditor.py --urls https://example.com
Scan Multiple Sites:
python site_auditor.py \
    --urls https://example.com,https://example.org
Scan URLs from a File:
python site_auditor.py --file targets.txt
Increase Thread Count
python site_auditor.py \
    --file targets.txt \
    --threads 20
Export Results to JSON:
python site_auditor.py \
    --urls https://example.com \
    --output json \
    --out-file report.json
Disable Local HTML Storage
python site_auditor.py \
    --urls https://example.com \
    --no-save-html
Example Terminal Output:
=== https://example.com ===
Links: 27
Forms: 3
Broken forms: 1
  Form 1: https://example.com/login (post) [2 inputs]
  Form 2: https://example.com/search (get) [1 inputs]
  Form 3:  (post) [0 inputs]

The tool is intentionally lightweight and focuses on static HTML analysis rather than browser automation. It does not execute JavaScript, follow discovered links recursively, submit forms, or perform security testing. Instead, it provides a fast first-pass assessment of site structure and form quality that can be incorporated into larger auditing, QA, scraping, or monitoring workflows.
Because sessions are stored in thread-local storage, each worker maintains its own connection pool while avoiding shared-session thread safety concerns. This design improves scalability while keeping implementation complexity low.

"""
import argparse
import json
import logging
import threading
from dataclasses import dataclass, asdict, field
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("SiteAuditor")
@dataclass(slots=True)
class FormInfo:
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)
@dataclass(slots=True)
class BrokenFormReport:
    missing_action: bool = False
    missing_inputs: bool = False
    suspicious_fields: list[str] = field(default_factory=list)
@dataclass(slots=True)
class PageReport:
    url: str
    forms: list[FormInfo] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    broken_forms: list[BrokenFormReport] = field(default_factory=list)
def create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update({
        "User-Agent": "SiteAuditor/2.0"
    })
    return session
class SiteAuditor:
    def __init__(self, urls, max_threads=5, output_mode="terminal", output_file=None, save_html=True):
        self.urls = urls if isinstance(urls, list) else [urls]
        self.max_threads = max_threads
        self.output_mode = output_mode
        self.output_file = Path(output_file) if output_file else None
        self.save_html_enabled = save_html
        self._thread_local = threading.local()
        self.results = []
        self.base_output = Path("audit_output")
        self.base_output.mkdir(exist_ok=True)
    def session(self):
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = create_session()
        return self._thread_local.session
    def fetch(self, url: str) -> str:
        r = self.session().get(url, timeout=(5, 20))
        r.raise_for_status()
        return r.text
    def save_html(self, domain_dir: Path, name: str, content: str):
        path = domain_dir / name
        path.write_text(content, encoding="utf-8")
        return str(path)
    def analyze(self, url: str) -> PageReport:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        logger.info(f"Scanning {url}")
        parsed = urlparse(url)
        domain = parsed.netloc.replace(":", "_")
        domain_dir = self.base_output / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        html = self.fetch(url)
        if self.save_html_enabled:
            self.save_html(domain_dir, "index.html", html)
        soup = BeautifulSoup(html, "html.parser")
        links = []
        forms = []
        broken_forms = []
        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            if urlparse(full).netloc == parsed.netloc:
                links.append(full)
        links = list(set(links))
        if self.save_html_enabled:
            map_file = domain_dir / "link_map.json"
            map_file.write_text(json.dumps(links, indent=2), encoding="utf-8")
        for i, form in enumerate(soup.find_all("form"), start=1):
            action = form.get("action")
            method = (form.get("method") or "get").lower()
            inputs = [
                {
                    "name": inp.get("name"),
                    "type": inp.get("type")
                }
                for inp in form.find_all("input")
            ]
            form_info = FormInfo(
                action=urljoin(url, action) if action else "",
                method=method,
                inputs=inputs
            )
            forms.append(form_info)
            broken = BrokenFormReport()
            if not action:
                broken.missing_action = True
            if not inputs:
                broken.missing_inputs = True
            for inp in inputs:
                if not inp.get("name"):
                    broken.suspicious_fields.append("missing_input_name")
                if inp.get("type") in (None, "", "text") and not inp.get("name"):
                    broken.suspicious_fields.append("anonymous_input")
            if broken.missing_action or broken.missing_inputs or broken.suspicious_fields:
                broken_forms.append(broken)
            if self.save_html_enabled:
                form_file = domain_dir / f"form_{i}.json"
                form_file.write_text(
                    json.dumps(asdict(form_info), indent=2),
                    encoding="utf-8"
                )
        return PageReport(
            url=url,
            forms=forms,
            links=links,
            broken_forms=broken_forms
        )
    def run(self):
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.analyze, u): u for u in self.urls}
            for f in as_completed(futures):
                try:
                    self.results.append(f.result())
                except Exception as e:
                    logger.error(f"Error: {e}")
        return self.results
    def output(self):
        if self.output_mode == "terminal":
            self.print_results()
        else:
            self.export_json()
    def print_results(self):
        for r in self.results:
            print(f"\n=== {r.url} ===")
            print(f"Links: {len(r.links)}")
            print(f"Forms: {len(r.forms)}")
            print(f"Broken forms: {len(r.broken_forms)}")
            for i, f in enumerate(r.forms, 1):
                print(f"  Form {i}: {f.action} ({f.method}) [{len(f.inputs)} inputs]")
    def export_json(self):
        data = [asdict(r) for r in self.results]
        if self.output_file:
            self.output_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.info(f"Saved JSON → {self.output_file}")
        else:
            print(json.dumps(data, indent=2))
def load_urls(args):
    if args.file:
        return [
            l.strip()
            for l in Path(args.file).read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
    return [u.strip() for u in args.urls.split(",") if u.strip()]
def main():
    parser = argparse.ArgumentParser(description="Site structure + form auditor")
    parser.add_argument("--urls", help="Comma-separated URLs")
    parser.add_argument("--file", help="File with URLs")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--output", choices=["terminal", "json"], default="terminal")
    parser.add_argument("--out-file", help="JSON output file")
    parser.add_argument("--no-save-html", action="store_true", help="Disable HTML saving")
    args = parser.parse_args()
    if not args.urls and not args.file:
        parser.error("Provide --urls or --file")
    urls = load_urls(args)
    auditor = SiteAuditor(
        urls=urls,
        max_threads=args.threads,
        output_mode=args.output,
        output_file=args.out_file,
        save_html=not args.no_save_html
    )
    auditor.run()
    auditor.output()
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
