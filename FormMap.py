#!/usr/bin/python3
"""
FormMap - Lightweight HTML structure and form auditing tool.
Static HTML analysis only:
- Retrieves HTML pages
- Maps internal links
- Optionally follows internal links with bounded crawling
- Inspects HTML forms
- Detects suspicious form structures
- Generates JSON reports
- Stores optional local artifacts
- Provides structured error reporting

No JavaScript execution.
No browser automation.
No form submission.
No active exploitation.

FormMap — Embedded Documentation:

FormMap is a lightweight multithreaded website structure auditing tool designed to inspect HTML pages, discover internal links, inventory forms, and generate structured reports about website organization and form implementation quality.

The tool is intentionally designed as a passive static analyzer. It retrieves HTML content, parses the document structure, extracts useful metadata, and records potential structural problems without interacting with forms or executing client-side code.

The primary components used are:
- `requests` for reliable HTTP retrieval
- `BeautifulSoup` for HTML parsing
- `ThreadPoolExecutor` for concurrent scanning
- Thread-local HTTP sessions for safe connection reuse

Key Features:

Concurrent Scanning:
Multiple websites can be analyzed simultaneously using a configurable thread pool.

The maximum number of worker threads is controlled with:

--threads NUMBER

Each worker maintains its own HTTP session to avoid thread-safety issues while allowing connection reuse and improved performance.

Automatic Retry Handling:
HTTP sessions include automatic retry support for temporary network failures and server responses including:

- HTTP 429
- HTTP 500
- HTTP 502
- HTTP 503
- HTTP 504

Retries use controlled backoff timing to reduce failures caused by temporary service conditions.

HTTP Error Handling:
Network failures are captured and converted into structured scan reports instead of terminating the entire scan.

Reported conditions include:

- Connection failures
- Timeouts
- SSL verification failures
- HTTP errors
- Request failures
- Unexpected processing errors

Each failure is stored with:

- Error category
- Error message
- HTTP status when available

Response Safety Controls:

FormMap limits downloaded content size to prevent excessive memory usage.

Default maximum response size:

10 MB

Redirect chains are also monitored.

Maximum redirects:

5

If limits are exceeded, the scan is safely marked as failed.

Internal Link Discovery:

The auditor collects anchor (`<a>`) elements containing `href` attributes and converts relative links into absolute URLs.

Example:

<a href="/contact">Contact</a>

becomes:

https://example.com/contact

Only links belonging to the same hostname are retained.

Duplicate links are automatically removed.

Optional Internal Link Crawling:

FormMap 3.0 adds:

--follow-internal-links

When enabled, FormMap will follow discovered internal links and analyze additional pages.

Crawler protections include:

- Same-domain restriction
- Duplicate URL prevention
- Maximum crawl depth
- Maximum crawl URL count

Default crawl limits:

Maximum depth:
1

Maximum URLs:
500

This provides additional website mapping capability while preventing uncontrolled crawling.

Example:

python FormMap.py \
    --urls https://example.com \
    --follow-internal-links

Form Analysis:

Every HTML form discovered is converted into a structured FormInfo object.

Collected information includes:

- Form action URL
- Submission method
- Input names
- Input types
- Required attributes
- Autocomplete values
- Placeholder values

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

Broken Form Detection:

FormMap attempts to identify incomplete or suspicious form structures.

A form may be flagged when:

- No action attribute exists
- No input fields exist
- An input field has no name
- Anonymous text inputs are present
- Form parsing fails

Example:

<form>
    <input type="text">
</form>

Potential report:

{
  "missing_action": true,
  "missing_inputs": false,
  "suspicious_fields": [
    "missing_input_name",
    "anonymous_input"
  ]
}

Optional Artifact Storage:

By default, FormMap creates:

audit_output/

Example:

audit_output/
└── example.com/
    └── 20260830_120000_a1b2c3d4/
        ├── index.html
        ├── link_map.json
        ├── form_1.json
        └── form_2.json

Stored artifacts include:

- Retrieved HTML pages
- Internal link maps
- Individual form definitions

Artifact storage can be disabled with:

--no-save-html

Reporting:

Results can be displayed directly in the terminal or exported as JSON.

Terminal output example:

=== https://example.com ===
Status: success
HTTP: 200
Depth: 0
Links: 27
Forms: 3
Broken forms: 1

Form 1:
https://example.com/login (post) [2 inputs]

Form 2:
https://example.com/search (get) [1 inputs]

Form 3:
(post) [0 inputs]

JSON export example:

python FormMap.py \
    --urls https://example.com \
    --output json \
    --out-file report.json

Command Line Usage:

Scan a single website:

python FormMap.py \
    --urls https://example.com

Scan multiple websites:

python FormMap.py \
    --urls https://example.com,https://example.org

Scan URLs from a file:

python FormMap.py \
    --file targets.txt

Increase worker threads:

python FormMap.py \
    --file targets.txt \
    --threads 20

Follow internal links:

python FormMap.py \
    --urls https://example.com \
    --follow-internal-links

Export JSON:

python FormMap.py \
    --urls https://example.com \
    --output json \
    --out-file report.json

Disable artifact saving:

python FormMap.py \
    --urls https://example.com \
    --no-save-html

Enable verbose logging:

python FormMap.py \
    --urls https://example.com \
    --verbose

Show version:

python FormMap.py \
    --version

Design Goals:

FormMap focuses on safe passive HTML analysis rather than browser automation or active security testing.

It does not:

- Execute JavaScript
- Submit forms
- Attempt authentication
- Perform vulnerability exploitation
- Modify remote systems

Instead, it provides a lightweight first-pass structural audit useful for:

- Website quality checks
- Documentation
- QA workflows
- Site inventory
- Development review
- Monitoring pipelines

Because sessions are stored using thread-local storage, each worker maintains its own HTTP connection pool while avoiding unsafe shared session access.

This design improves scalability while keeping the implementation simple, predictable, and maintainable.
"""
import argparse
import json
import logging
import threading
import tempfile
import time
import uuid
from dataclasses import dataclass,asdict,field
from pathlib import Path
from urllib.parse import urljoin,urlparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.exceptions import (
    ConnectionError,
    Timeout,
    HTTPError,
    SSLError,
    RequestException
)
from urllib3.util.retry import Retry
VERSION="3.1"
MAX_RESPONSE_SIZE=10*1024*1024
MAX_THREADS=50
MAX_REDIRECTS=5
MAX_CRAWL_DEPTH=1
MAX_CRAWL_URLS=500
DEFAULT_TIMEOUT=(5,20)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger=logging.getLogger("FormMap")
@dataclass(slots=True)
class ScanError:
    category:str
    message:str
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
    status:str="unknown"
    http_status:int=0
    elapsed:float=0.0
    crawl_depth:int=0
    forms:list[FormInfo]=field(default_factory=list)
    links:list[str]=field(default_factory=list)
    broken_forms:list[BrokenFormReport]=field(default_factory=list)
    errors:list[ScanError]=field(default_factory=list)
def safe_filename(value:str)->str:
    return "".join(
        c if c.isalnum() or c in "._-" else "_"
        for c in value
    )
def normalize_url(url:str):
    if not url:
        return None
    try:
        url=url.strip()
        if not url:
            return None
        if not url.startswith(
            (
                "http://",
                "https://"
            )
        ):
            url="https://"+url
        parsed=urlparse(url)
        if parsed.scheme not in (
            "http",
            "https"
        ):
            return None
        if not parsed.hostname:
            return None
        normalized=parsed._replace(
            fragment=""
        ).geturl()
        return normalized.rstrip("/")
    except Exception:
        return None
def domain_name(url:str)->str:
    try:
        parsed=urlparse(url)
        return safe_filename(
            parsed.hostname or "unknown"
        )
    except Exception:
        return "unknown"
def atomic_write(path:Path,data:str):
    temp_name=None
    try:
        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            encoding="utf-8",
            dir=str(path.parent)
        ) as tmp:
            tmp.write(data)
            temp_name=tmp.name
        Path(temp_name).replace(
            path
        )
        temp_name=None
    except Exception:
        logger.exception(
            "Atomic write failed: %s",
            path
        )
    finally:
        if temp_name:
            try:
                temp_path=Path(temp_name)
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
def create_session():
    session=requests.Session()
    retry=Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.5,
        status_forcelist=[
            429,
            500,
            502,
            503,
            504
        ],
        allowed_methods=[
            "GET"
        ],
        raise_on_status=False
    )
    adapter=HTTPAdapter(
        max_retries=retry,
        pool_connections=10,
        pool_maxsize=10
    )
    session.mount(
        "http://",
        adapter
    )
    session.mount(
        "https://",
        adapter
    )
    session.headers.update({
        "User-Agent":
            "Mozilla/5.0 "
            "(X11; Linux x86_64) "
            "FormMap/"+VERSION,
        "Accept":
            "text/html,application/xhtml+xml",
        "Accept-Language":
            "en-US,en;q=0.9",
        "Accept-Encoding":
            "identity",
        "Connection":
            "keep-alive"
    })
    return session
class SiteAuditor:
    def __init__(
        self,
        urls,
        max_threads=5,
        output_mode="terminal",
        output_file=None,
        save_html=True,
        follow_internal_links=False
    ):
        self.urls=[]
        for url in urls:
            normalized=normalize_url(url)
            if normalized:
                self.urls.append(normalized)
        self.urls=list(dict.fromkeys(self.urls))
        self.max_threads=max(
            1,
            min(
                max_threads,
                MAX_THREADS
            )
        )
        self.output_mode=output_mode
        self.output_file=Path(output_file) if output_file else None
        self.save_html_enabled=save_html
        self.follow_internal_links=follow_internal_links
        self.thread_local=threading.local()
        self.results=[]
        self.results_lock=threading.Lock()
        self.visited=set()
        self.visited_lock=threading.Lock()
        self.base_output=Path(
            "audit_output"
        )
        self.base_output.mkdir(
            exist_ok=True
        )
    def session(self):
        if not hasattr(
            self.thread_local,
            "session"
        ):
            self.thread_local.session=create_session()
        return self.thread_local.session
    def close_session(self):
        session=getattr(
            self.thread_local,
            "session",
            None
        )
        if session:
            try:
                session.close()
            except Exception:
                pass
    def fetch(self,url):
        try:
            response=self.session().get(
                url,
                timeout=DEFAULT_TIMEOUT,
                stream=True,
                allow_redirects=True
            )
            if len(response.history)>MAX_REDIRECTS:
                raise ValueError(
                    "Too many redirects"
                )
            response.raise_for_status()
            content_type=response.headers.get(
                "Content-Type",
                ""
            ).lower()
            if content_type and not any(
                allowed in content_type
                for allowed in (
                    "text/html",
                    "application/xhtml+xml"
                )
            ):
                raise RuntimeError(
                    "Unsupported content type: "
                    + content_type
                )
            size=0
            chunks=[]
            for chunk in response.iter_content(
                8192
            ):
                if chunk:
                    size+=len(chunk)
                    if size>MAX_RESPONSE_SIZE:
                        raise ValueError(
                            "Response exceeded size limit"
                        )
                    chunks.append(chunk)
            content=b"".join(
                chunks
            ).decode(
                "utf-8",
                errors="replace"
            )
            return content,response.status_code
        except HTTPError as e:
            status=e.response.status_code if e.response else 0
            raise RuntimeError(
                f"HTTP error: {status}"
            )
        except Timeout:
            raise RuntimeError(
                "Request timed out"
            )
        except SSLError:
            raise RuntimeError(
                "SSL verification failed"
            )
        except ConnectionError:
            raise RuntimeError(
                "Connection failed"
            )
        except RequestException as e:
            raise RuntimeError(
                f"Request failed: {e}"
            )
    def save_html(
        self,
        folder,
        name,
        content
    ):
        path=folder/name
        atomic_write(
            path,
            content
        )
        return str(path)
    def extract_links(
        self,
        soup,
        url
    ):
        links=set()
        try:
            base=urlparse(url).hostname
            for tag in soup.find_all(
                "a",
                href=True
            ):
                try:
                    full=urljoin(
                        url,
                        tag["href"]
                    )
                    parsed=urlparse(
                        full
                    )
                    if parsed.hostname==base:
                        clean=parsed._replace(
                            fragment=""
                        ).geturl()
                        links.add(
                            clean.rstrip("/")
                        )
                except Exception:
                    continue
        except Exception:
            logger.exception(
                "Link extraction failed"
            )
        return sorted(
            links
        )
    def inspect_form(
        self,
        form,
        url
    ):
        try:
            action=form.get(
                "action"
            )
            method=(
                form.get("method")
                or "get"
            ).lower()
            inputs=[]
            suspicious=set()
            for inp in form.find_all(
                [
                    "input",
                    "textarea",
                    "select",
                    "button"
                ]
            ):
                tag_name=inp.name
                data={
                    "element":tag_name,
                    "name":inp.get("name"),
                    "type":inp.get("type"),
                    "required":inp.has_attr(
                        "required"
                    ),
                    "autocomplete":inp.get(
                        "autocomplete"
                    ),
                    "placeholder":inp.get(
                        "placeholder"
                    )
                }
                inputs.append(
                    data
                )
                if not data["name"]:
                    suspicious.add(
                        "missing_input_name"
                    )
                    if (
                        data["type"] in
                        (
                            None,
                            "",
                            "text"
                        )
                        or tag_name in
                        (
                            "textarea",
                            "select"
                        )
                    ):
                        suspicious.add(
                            "anonymous_input"
                        )
            info=FormInfo(
                action=urljoin(
                    url,
                    action
                )
                if action
                else "",
                method=method,
                inputs=inputs
            )
            broken=BrokenFormReport(
                missing_action=not bool(
                    action
                ),
                missing_inputs=not bool(
                    inputs
                ),
                suspicious_fields=sorted(
                    suspicious
                )
            )
            return info,broken
        except Exception:
            return (
                FormInfo(
                    action="",
                    method="unknown",
                    inputs=[]
                ),
                BrokenFormReport(
                    suspicious_fields=[
                        "form_parse_error"
                    ]
                )
            )
    def analyze(
        self,
        url,
        depth=0
    ):
        start=time.time()
        report=PageReport(
            url=url,
            crawl_depth=depth
        )
        logger.info(
            "Scanning %s",
            url
        )
        folder=self.base_output/domain_name(
            url
        )
        timestamp=(
            time.strftime(
                "%Y%m%d_%H%M%S"
            )
            +"_"
            +uuid.uuid4().hex[:8]
        )
        scan_folder=folder/timestamp
        scan_folder.mkdir(
            parents=True,
            exist_ok=True
        )
        try:
            html,status=self.fetch(
                url
            )
            report.http_status=status
            report.status="success"
            if self.save_html_enabled:
                self.save_html(
                    scan_folder,
                    "index.html",
                    html
                )
            soup=BeautifulSoup(
                html,
                "html.parser"
            )
            report.links=self.extract_links(
                soup,
                url
            )
            if self.save_html_enabled:
                atomic_write(
                    scan_folder/"link_map.json",
                    json.dumps(
                        report.links,
                        indent=2
                    )
                )
            for index,form in enumerate(
                soup.find_all("form"),
                1
            ):
                info,broken=self.inspect_form(
                    form,
                    url
                )
                report.forms.append(
                    info
                )
                if (
                    broken.missing_action
                    or broken.missing_inputs
                    or broken.suspicious_fields
                ):
                    report.broken_forms.append(
                        broken
                    )
                if self.save_html_enabled:
                    atomic_write(
                        scan_folder/
                        f"form_{index}.json",
                        json.dumps(
                            asdict(info),
                            indent=2
                        )
                    )
        except RuntimeError as e:
            message=str(e)
            report.status="failed"
            report.errors.append(
                ScanError(
                    category="network",
                    message=message
                )
            )
            logger.warning(
                "%s failed: %s",
                url,
                message
            )
        except Exception as e:
            report.status="failed"
            report.errors.append(
                ScanError(
                    category="unexpected",
                    message=str(e)
                )
            )
            logger.exception(
                "Unexpected scan failure: %s",
                url
            )
        report.elapsed=round(
            time.time()-start,
            3
        )
        self.close_session()
        return report
    def crawl_internal(
        self,
        start_url
    ):
        queue=[
            (
                start_url,
                0
            )
        ]
        reports=[]
        while queue:
            if len(reports)>=MAX_CRAWL_URLS:
                logger.warning(
                    "Maximum crawl URL limit reached"
                )
                break
            url,depth=queue.pop(0)
            if depth>MAX_CRAWL_DEPTH:
                continue
            with self.visited_lock:
                if url in self.visited:
                    continue
                self.visited.add(
                    url
                )
            report=self.analyze(
                url,
                depth
            )
            reports.append(
                report
            )
            if (
                self.follow_internal_links
                and report.status=="success"
            ):
                for link in report.links:
                    if link not in self.visited:
                        queue.append(
                            (
                                link,
                                depth+1
                            )
                        )
        return reports
    def run(self):
        with ThreadPoolExecutor(
            max_workers=self.max_threads
        ) as executor:
            jobs={}
            for url in self.urls:
                if self.follow_internal_links:
                    future=executor.submit(
                        self.crawl_internal,
                        url
                    )
                else:
                    future=executor.submit(
                        self.analyze,
                        url
                    )
                jobs[future]=url
            for future in as_completed(jobs):
                try:
                    result=future.result()
                    if isinstance(
                        result,
                        list
                    ):
                        with self.results_lock:
                            self.results.extend(
                                result
                            )
                    else:
                        with self.results_lock:
                            self.results.append(
                                result
                            )
                except Exception as e:
                    logger.exception(
                        "Worker failure for %s",
                        jobs[future]
                    )
                    with self.results_lock:
                        self.results.append(
                            PageReport(
                                url=jobs[future],
                                status="failed",
                                errors=[
                                    ScanError(
                                        category="worker",
                                        message=str(e)
                                    )
                                ]
                            )
                        )
        self.results.sort(
            key=lambda x:x.url
        )
        return self.results
    def print_results(self):
        for report in self.results:
            print()
            print(
                "=== "+report.url+" ==="
            )
            print(
                "Status:",
                report.status
            )
            print(
                "Depth:",
                report.crawl_depth
            )
            if report.http_status:
                print(
                    "HTTP:",
                    report.http_status
                )
            if report.elapsed:
                print(
                    "Time:",
                    report.elapsed,
                    "seconds"
                )
            if report.errors:
                for error in report.errors:
                    print(
                        "Error:",
                        error.category,
                        error.message
                    )
            print(
                "Links:",
                len(report.links)
            )
            print(
                "Forms:",
                len(report.forms)
            )
            print(
                "Broken forms:",
                len(report.broken_forms)
            )
            for number,form in enumerate(
                report.forms,
                1
            ):
                print(
                    f"  Form {number}: "
                    f"{form.action} "
                    f"({form.method}) "
                    f"[{len(form.inputs)} inputs]"
                )
    def export_json(self):
        data=json.dumps(
            [
                asdict(report)
                for report in self.results
            ],
            indent=2
        )
        if self.output_file:
            atomic_write(
                self.output_file,
                data
            )
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
    urls=[]
    if args.file:
        try:
            urls.extend(
                [
                    line.strip()
                    for line in Path(args.file)
                    .read_text(
                        encoding="utf-8"
                    )
                    .splitlines()
                    if line.strip()
                ]
            )
        except Exception:
            logger.exception(
                "Failed reading URL file"
            )
    if args.urls:
        urls.extend(
            [
                item.strip()
                for item in args.urls.split(",")
                if item.strip()
            ]
        )
    return urls
def main():
    parser=argparse.ArgumentParser(
        description=(
            "FormMap - Static HTML "
            "structure and form auditor"
        )
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
        choices=[
            "terminal",
            "json"
        ],
        default="terminal",
        help="Output format"
    )
    parser.add_argument(
        "--out-file",
        help="JSON output file"
    )
    parser.add_argument(
        "--no-save-html",
        action="store_true",
        help="Disable HTML artifact saving"
    )
    parser.add_argument(
        "--follow-internal-links",
        action="store_true",
        help=(
            "Follow same-domain internal links "
            "with bounded crawl depth"
        )
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show FormMap version"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    args=parser.parse_args()
    if args.version:
        print(
            "FormMap",
            VERSION
        )
        return
    if args.verbose:
        logger.setLevel(
            logging.DEBUG
        )
    if not args.urls and not args.file:
        parser.error(
            "Provide --urls or --file"
        )
    urls=[
        u
        for u in load_urls(args)
        if normalize_url(u)
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
        save_html=not args.no_save_html,
        follow_internal_links=args.follow_internal_links
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
