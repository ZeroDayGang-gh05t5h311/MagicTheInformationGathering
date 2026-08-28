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

FormMap - Lightweight HTML structure and form auditing tool.
Static analysis only:
- Retrieves HTML pages
- Maps internal links
- Inspects forms
- Generates JSON reports
- Stores optional local artifacts

No JavaScript execution.
No form submission.
No active exploitation.
"""
import argparse
import json
import logging
import threading
import tempfile
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s")
logger=logging.getLogger("FormMap")

MAX_RESPONSE_SIZE=10*1024*1024
MAX_THREADS=50

@dataclass(slots=True)
class FormInfo:
    action:str
    method:str
    inputs:list[dict]=field(default_factory=list)

@dataclass(slots=True)
class BrokenFormReport:
    missing_action:bool=False
    missing_inputs:bool=False
    suspicious_fields:list[str]=field(default_factory=list)

@dataclass(slots=True)
class PageReport:
    url:str
    forms:list[FormInfo]=field(default_factory=list)
    links:list[str]=field(default_factory=list)
    broken_forms:list[BrokenFormReport]=field(default_factory=list)

def safe_filename(value:str)->str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in value)

def normalize_url(url:str):
    if not url:
        return None
    url=url.strip()
    if not url:
        return None
    if not url.startswith(("http://","https://")):
        url="https://"+url
    try:
        parsed=urlparse(url)
        if parsed.scheme not in ("http","https"):
            return None
        if not parsed.hostname:
            return None
        return url
    except Exception:
        return None

def domain_name(url:str)->str:
    parsed=urlparse(url)
    return safe_filename(parsed.hostname or "unknown")

def atomic_write(path:Path,data:str):
    try:
        path.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            encoding="utf-8",
            dir=str(path.parent)
        ) as tmp:
            tmp.write(data)
            temp_name=tmp.name
        Path(temp_name).replace(path)
    except Exception:
        logger.exception("Atomic write failed")

def create_session()->requests.Session:
    session=requests.Session()
    retry=Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500,502,503,504],
        allowed_methods=["GET"]
    )
    adapter=HTTPAdapter(
        max_retries=retry,
        pool_connections=10,
        pool_maxsize=10
    )
    session.mount("http://",adapter)
    session.mount("https://",adapter)
    session.headers.update({
        "User-Agent":"Mozilla/5.0 (compatible; FormMap/1.0)"
    })
    return session
class SiteAuditor:
    def __init__(self,urls,max_threads=5,output_mode="terminal",output_file=None,save_html=True):
        self.urls=[normalize_url(u) for u in urls if normalize_url(u)]
        self.max_threads=max(1,min(max_threads,MAX_THREADS))
        self.output_mode=output_mode
        self.output_file=Path(output_file) if output_file else None
        self.save_html_enabled=save_html
        self.thread_local=threading.local()
        self.results=[]
        self.base_output=Path("audit_output")
        self.base_output.mkdir(exist_ok=True)
    def session(self):
        if not hasattr(self.thread_local,"session"):
            self.thread_local.session=create_session()
        return self.thread_local.session
    def fetch(self,url):
        response=self.session().get(url,timeout=(5,20),stream=True)
        response.raise_for_status()
        size=0
        chunks=[]
        for chunk in response.iter_content(8192):
            size+=len(chunk)
            if size>MAX_RESPONSE_SIZE:
                raise ValueError("Response exceeded size limit")
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8",errors="replace")
    def save_html(self,folder,name,content):
        path=folder/name
        atomic_write(path,content)
        return str(path)
    def extract_links(self,soup,url):
        links=set()
        base=urlparse(url).hostname
        for tag in soup.find_all("a",href=True):
            try:
                full=urljoin(url,tag["href"])
                parsed=urlparse(full)
                if parsed.hostname==base:
                    links.add(full)
            except Exception:
                continue
        return sorted(links)
    def inspect_form(self,form,url):
        action=form.get("action")
        method=(form.get("method") or "get").lower()
        inputs=[]
        suspicious=set()
        for inp in form.find_all("input"):
            data={
                "name":inp.get("name"),
                "type":inp.get("type"),
                "required":inp.has_attr("required"),
                "autocomplete":inp.get("autocomplete"),
                "placeholder":inp.get("placeholder")
            }
            inputs.append(data)
            if not data["name"]:
                suspicious.add("missing_input_name")
                if data["type"] in (None,"","text"):
                    suspicious.add("anonymous_input")
        info=FormInfo(
            action=urljoin(url,action) if action else "",
            method=method,
            inputs=inputs
        )
        broken=BrokenFormReport(
            missing_action=not bool(action),
            missing_inputs=not bool(inputs),
            suspicious_fields=sorted(suspicious)
        )
        return info,broken
    def analyze(self,url):
        logger.info("Scanning %s",url)
        parsed=urlparse(url)
        folder=self.base_output/domain_name(url)
        timestamp=time.strftime("%Y%m%d_%H%M%S")
        scan_folder=folder/timestamp
        scan_folder.mkdir(parents=True,exist_ok=True)
        html=self.fetch(url)
        if self.save_html_enabled:
            self.save_html(scan_folder,"index.html",html)
        soup=BeautifulSoup(html,"html.parser")
        links=self.extract_links(soup,url)
        if self.save_html_enabled:
            atomic_write(
                scan_folder/"link_map.json",
                json.dumps(links,indent=2)
            )
        forms=[]
        broken_forms=[]
        for index,form in enumerate(soup.find_all("form"),1):
            info,broken=self.inspect_form(form,url)
            forms.append(info)
            if (
                broken.missing_action
                or broken.missing_inputs
                or broken.suspicious_fields
            ):
                broken_forms.append(broken)
            if self.save_html_enabled:
                atomic_write(
                    scan_folder/f"form_{index}.json",
                    json.dumps(asdict(info),indent=2)
                )
        return PageReport(
            url=url,
            forms=forms,
            links=links,
            broken_forms=broken_forms
        )
    def run(self):
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            jobs={
                executor.submit(self.analyze,url):url
                for url in self.urls
            }
            for future in as_completed(jobs):
                try:
                    self.results.append(future.result())
                except Exception:
                    logger.exception(
                        "Scan failed for %s",
                        jobs[future]
                    )
        return self.results
    def print_results(self):
        for report in self.results:
            print()
            print("=== "+report.url+" ===")
            print("Links:",len(report.links))
            print("Forms:",len(report.forms))
            print("Broken forms:",len(report.broken_forms))
            for number,form in enumerate(report.forms,1):
                print(
                    f"  Form {number}: "
                    f"{form.action} "
                    f"({form.method}) "
                    f"[{len(form.inputs)} inputs]"
                )
    def export_json(self):
        data=json.dumps(
            [asdict(r) for r in self.results],
            indent=2
        )
        if self.output_file:
            atomic_write(self.output_file,data)
            logger.info(
                "Saved JSON -> %s",
                self.output_file
            )
        else:
            print(data)
    def output(self):
        if self.output_mode=="json":
            self.export_json()
        else:
            self.print_results()
def load_urls(args):
    if args.file:
        try:
            return [
                normalize_url(line.strip())
                for line in Path(args.file).read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]
        except Exception:
            logger.exception("Failed reading URL file")
            return []
    return [
        normalize_url(url.strip())
        for url in args.urls.split(",")
        if url.strip()
    ]
def main():
    parser=argparse.ArgumentParser(
        description="FormMap - HTML structure and form auditor"
    )
    parser.add_argument(
        "--urls",
        help="Comma separated URLs"
    )
    parser.add_argument(
        "--file",
        help="Text file containing URLs"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Maximum worker threads"
    )
    parser.add_argument(
        "--output",
        choices=["terminal","json"],
        default="terminal"
    )
    parser.add_argument(
        "--out-file",
        help="JSON output file"
    )
    parser.add_argument(
        "--no-save-html",
        action="store_true",
        help="Disable HTML and artifact saving"
    )
    args=parser.parse_args()
    if not args.urls and not args.file:
        parser.error(
            "Provide --urls or --file"
        )
    urls=[
        u for u in load_urls(args)
        if u
    ]
    if not urls:
        parser.error(
            "No valid URLs supplied"
        )
    auditor=SiteAuditor(
        urls=urls,
        max_threads=args.threads,
        output_mode=args.output,
        output_file=args.out_file,
        save_html=not args.no_save_html
    )
    auditor.run()
    auditor.output()
if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info(
            "Interrupted by user"
        )
d
