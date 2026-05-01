#!/usr/bin/python3
"""
jsmapper.py is an asynchronous, object-oriented reconnaissance tool for web applications. 
It crawls web pages, extracts links, forms, and JavaScript files, and identifies potential security issues. 
Key features include:
- Parsing HTML to enumerate links, forms, and input parameters
- Scanning for XSS patterns, DOM-based XSS risks, and sensitive information (emails, API keys, JWT tokens)
- Extracting endpoints from JavaScript files
- Checking for missing critical security headers
- Optional XSS fuzzing and reflection testing for input parameters
- Multi-threaded asynchronous fetching with rate-limit handling and optional stealth mode
- Optional recursive scanning of internal links to a configurable depth
- JSON output for automated analysis
Scan a single URL with default settings:
python3 jsmapper.py -u https://example.com
Scan multiple targets from a file, save results, and enable stealth mode
python3 jsmapper.py -l targets.txt --output results.json --stealth
Increase concurrency and enable HTML saving
python3 jsmapper.py -u https://example.com -t 20 --save-html
"""
import asyncio, aiohttp, re, argparse, json, logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, ParseResult
from typing import Dict, List, Any, Optional, Tuple, Set
class PassiveHTMLScanner:
    def __init__(self, threads=10, delay=0.0, retries=2, save_html=False, depth=0, output=None, stealth=False, performance=False):
        self.threads = threads
        self.delay = delay
        self.retries = retries
        self.save_html = save_html
        self.depth = depth
        self.output = output
        self.stealth = stealth
        self.performance = performance  
        self.semaphore = asyncio.Semaphore(threads)
        self.lock = asyncio.Lock()
        self.completed = 0
        self.total_targets = 0
        logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
        self.DEFAULT_HEADERS: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        # XSS payloads to test for vulnerabilities
        self.XSS_PAYLOADS: List[str] = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
        ]
        self.RATE_LIMIT_STATUSES: Set[int] = {429, 403}
        self.RATE_LIMIT_KEYWORDS: List[str] = [
            "rate limit", "too many requests", "access denied",
            "temporarily blocked", "captcha",
        ]
    def normalize_url(self, url: Optional[str]) -> Optional[str]:
        try:
            if not url:
                return None
            if not url.startswith(("http://", "https://")):
                return "https://" + url
            return url
        except Exception as e:
            logging.debug(f"normalize_url error: {e}")
            return None
    def is_rate_limited(self, status: int, text: str) -> bool:
        try:
            if status in self.RATE_LIMIT_STATUSES:
                return True
            if text:
                lowered = text.lower()
                return any(k in lowered for k in self.RATE_LIMIT_KEYWORDS)
        except Exception as e:
            logging.debug(f"rate limit check error: {e}")
        return False
    def is_same_domain(self, base: str, target: str) -> bool:
        try:
            return urlparse(base).netloc == urlparse(target).netloc
        except Exception:
            return False
    async def fetch_page(self, session, url: str) -> Tuple:
        attempt = 0
        backoff = self.delay or 1.0
        while attempt <= self.retries:
            try:
                if self.delay:
                    await asyncio.sleep(self.delay)
                logging.info(f"[+] Fetching: {url} (attempt {attempt + 1})")
                headers = self.DEFAULT_HEADERS
                if self.stealth:
                    # Modify headers to be more stealthy (spoofing User-Agent)
                    headers = {**self.DEFAULT_HEADERS, "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:54.0) Gecko/20100101 Firefox/140.1"}
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers=headers
                ) as response:
                    content_type = response.headers.get("Content-Type", "")
                    final_url = str(response.url)
                    try:
                        text = await response.text(errors="ignore")
                    except Exception as e:
                        logging.debug(f"text read error: {e}")
                        text = ""
                    if self.is_rate_limited(response.status, text):
                        logging.warning(f"[!] Rate limited: {url}")
                        await asyncio.sleep(backoff * 2)
                        backoff *= 2
                        attempt += 1
                        continue
                    if "html" not in content_type.lower():
                        return None, response.status, dict(response.headers), final_url
                    return text, response.status, dict(response.headers), final_url
            except Exception as e:
                logging.error(f"[!] Fetch error: {e}")
            attempt += 1
            await asyncio.sleep(backoff)
            backoff *= 2
        return None, None, {}, url
    def parse_html(self, html: Optional[str], base_url: str):
        try:
            if not html:
                return [], None, [], []
            soup = BeautifulSoup(html, "html.parser")
            results, links, forms = [], [], []
            for link in soup.find_all("a", href=True):
                try:
                    href = urljoin(base_url, link.get("href", ""))
                    if not href or href.startswith(("javascript:", "mailto:", "#")):
                        continue
                    title = link.get_text(strip=True) or "N/A"
                    results.append({"title": title, "url": href})
                    links.append(href)
                except Exception as e:
                    logging.debug(e)
            for form in soup.find_all("form"):
                try:
                    action = urljoin(base_url, form.get("action") or "")
                    method = (form.get("method") or "get").lower()
                    inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
                    forms.append({"action": action, "method": method, "inputs": inputs})
                except Exception as e:
                    logging.debug(e)
            return results, soup, links, forms
        except Exception as e:
            logging.error(f"[!] Parsing error: {e}")
            return [], None, [], []
    def scan_for_xss_patterns(self, html):
        patterns = {
            "inline_script": r"<script.*?>.*?</script>",
            "event_handlers": r"on\w+\s*=",
            "javascript_urls": r"javascript:",
            "iframe_tags": r"<iframe.*?>",
            "eval_usage": r"eval\s*\(",
        }
        results = {}
        for k, p in patterns.items():
            try:
                matches = re.findall(p, html, re.I | re.S)
                if matches:
                    results[k] = len(matches)
            except re.error as e:
                logging.debug(e)
        return results
    def scan_for_dom_xss_patterns(self, html):
        patterns = {
            "innerHTML_usage": r"\.innerHTML\s*=",
            "url_params": r"URLSearchParams\s*\(",
            "location_search": r"location\.search",
            "dom_targeting": r"getElementById\s*\(",
        }
        results = {}
        for k, p in patterns.items():
            try:
                matches = re.findall(p, html, re.I)
                if matches:
                    results[k] = len(matches)
            except re.error as e:
                logging.debug(e)
        return results
    def scan_sensitive_info(self, html):
        patterns = {
            "emails": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "api_keys": r"(?i)(api[_-]?key\s*=\s*['\"]?[A-Za-z0-9_\-]{16,})",
            "jwt_tokens": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        }
        results = {}
        for k, p in patterns.items():
            try:
                matches = re.findall(p, html)
                if matches:
                    results[k] = len(matches)
            except re.error as e:
                logging.debug(e)
        return results
    def check_security_headers(self, headers):
        important = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
        ]
        try:
            return [h for h in important if h not in headers]
        except Exception as e:
            logging.debug(e)
            return []
    def extract_js_files(self, soup, base_url):
        results = []
        if not soup:
            return results
        for script in soup.find_all("script", src=True):
            try:
                src = script.get("src")
                if src:
                    results.append(urljoin(base_url, src))
            except Exception as e:
                logging.debug(e)
        return results
    def extract_endpoints_from_js(self, js):
        patterns = [
            r"https?://[^\s\"']+",
            r"/[a-zA-Z0-9_\-/]+",
            r"[a-zA-Z0-9_\-/]+\.(php|json|asp|jsp)",
            r"['\"](/api/[^\s'\"]+)['\"]",
            r"['\"](https?://[^\s'\"]+)['\"]",
        ]
        found = set()
        for pattern in patterns:
            try:
                found.update(re.findall(pattern, js))
            except re.error as e:
                logging.debug(e)
        return list(found)
    async def analyze_js_files(self, session, js_files):
        endpoints = set()
        for js_url in js_files:
            try:
                logging.info(f"[+] Fetching JS: {js_url}")
                async with session.get(js_url, headers=self.DEFAULT_HEADERS) as res:
                    if res.status != 200:
                        continue
                    text = await res.text(errors="ignore")
                    endpoints.update(self.extract_endpoints_from_js(text))
            except Exception as e:
                logging.debug(e)
        return list(endpoints)
    def extract_parameters(self, url):
        try:
            parsed = urlparse(url)
            params = {}
            if parsed.query:
                for p in parsed.query.split("&"):
                    if "=" in p:
                        k, v = p.split("=", 1)
                        params[k] = v
            return params
        except Exception as e:
            logging.debug(e)
            return {}
    async def fuzz_xss(self, session, url, params):
        findings = {}
        for param in params:
            findings[param] = []
            for payload in self.XSS_PAYLOADS:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    await asyncio.sleep(0.2)
                    async with session.get(url, params=test_params, headers=self.DEFAULT_HEADERS) as res:
                        text = await res.text(errors="ignore")
                        if text and payload in text:
                            findings[param].append(payload)
                except Exception as e:
                    logging.debug(e)
        return {k: v for k, v in findings.items() if v}
    async def test_reflection(self, session, url, params):
        reflected = []
        for p in params:
            try:
                marker = "scanner_test_123"
                test_params = params.copy()
                test_params[p] = marker
                await asyncio.sleep(0.2)
                async with session.get(url, params=test_params, headers=self.DEFAULT_HEADERS) as res:
                    text = await res.text(errors="ignore")
                    if text and marker in text:
                        reflected.append(p)
            except Exception as e:
                logging.debug(e)
        return reflected
    async def process_url(self, session, url, depth_level=0):
        async with self.semaphore:
            html, status, headers, final_url = await self.fetch_page(session, url)
        result = {
            "url": url,
            "final_url": final_url,
            "status_code": status,
            "links": [],
            "forms": [],
            "headers": headers,
            "missing_security_headers": [],
            "xss_patterns": {},
            "dom_xss_patterns": {},
            "sensitive_info": {},
            "js_files": [],
            "endpoints": [],
            "parameters": {},
            "reflected_params": [],
            "xss_fuzz": {},
        }
        if status:
            result["missing_security_headers"] = self.check_security_headers(headers)
        if html and len(html) > 50:
            if self.save_html:
                safe_name = re.sub(r'[^a-zA-Z0-9]', '_', urlparse(url).netloc)
                with open(f"dump_{safe_name}.html", "w", encoding="utf-8") as f:
                    f.write(html)
            data, soup, links, forms = self.parse_html(html, url)
            result["links"] = data
            result["forms"] = forms
            result["xss_patterns"] = self.scan_for_xss_patterns(html)
            result["dom_xss_patterns"] = self.scan_for_dom_xss_patterns(html)
            result["sensitive_info"] = self.scan_sensitive_info(html)
            js_files = self.extract_js_files(soup, url)
            result["js_files"] = js_files
            if js_files:
                result["endpoints"] = await self.analyze_js_files(session, js_files)
            params = self.extract_parameters(url)
            result["parameters"] = params
            if params:
                result["reflected_params"] = await self.test_reflection(session, url, params)
                result["xss_fuzz"] = await self.fuzz_xss(session, url, params)
            # Handle link recursion for depth
            if depth_level < self.depth:
                tasks = [
                    self.process_url(session, l, depth_level + 1)
                    for l in links[:10]
                    if self.is_same_domain(url, l)
                ]
                await asyncio.gather(*tasks, return_exceptions=True)
        # Progress tracking
        async with self.lock:
            self.completed += 1
            percent = (self.completed / self.total_targets * 100) if self.total_targets else 0
            print(f"[+] Progress: {self.completed}/{self.total_targets} ({percent:.2f}%)")
        return result
    def pretty_print(self, r):
        print(f"\n=== {r['url']} ===")
        print(f"[Status] {r['status_code']} -> {r['final_url']}")
        if r["links"]:
            print("\n[Links]")
            for l in r["links"]:
                print(f"- {l['title']} -> {l['url']}")
        if r["forms"]:
            print("\n[Forms]")
            for f in r["forms"]:
                print(f"- {f}")
        if r["js_files"]:
            print("\n[JS Files]")
            for j in r["js_files"]:
                print(f"- {j}")
        if r["endpoints"]:
            print("\n[Endpoints]")
            for e in r["endpoints"]:
                print(f"- {e}")
        if r["parameters"]:
            print("\n[Params]")
            for k, v in r["parameters"].items():
                print(f"- {k}={v}")
        if r["reflected_params"]:
            print("\n[Reflected]")
            for p in r["reflected_params"]:
                print(f"- {p}")
        if r["xss_fuzz"]:
            print("\n[XSS Fuzz Findings]")
            for param, payloads in r["xss_fuzz"].items():
                print(f"- {param}:")
                for p in payloads:
                    print(f"  -> {p}")
    async def run(self, targets):
        self.total_targets = len(targets)
        connector = aiohttp.TCPConnector(limit=50, ssl=True)
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self.process_url(session, url) for url in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        clean_results = []
        for r in results:
            if isinstance(r, Exception):
                print(f"[!] Task failed: {r}")
                continue
            self.pretty_print(r)
            clean_results.append(r)
        if self.output:
            with open(self.output, "w") as f:
                json.dump(clean_results, f, indent=2)
        return clean_results
async def main():
    parser = argparse.ArgumentParser(description="jsmapper.py")
    parser.add_argument("-u", "--url")
    parser.add_argument("-l", "--list")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--save-html", action="store_true")
    parser.add_argument("--depth", type=int, default=0)
    parser.add_argument("--output", help="Save results to JSON")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--performance", action="store_true", help="Enable performance mode")
    args = parser.parse_args()
    scanner = PassiveHTMLScanner(
        threads=args.threads,
        delay=args.delay,
        retries=args.retries,
        save_html=args.save_html,
        depth=args.depth,
        output=args.output,
        stealth=args.stealth,
        performance=args.performance
    )
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list, encoding="utf-8") as f:
                targets.extend([x.strip() for x in f if x.strip()])
        except Exception as e:
            print(f"[!] Failed to read list: {e}")
            return
    targets = list({scanner.normalize_url(t) for t in targets if scanner.normalize_url(t)})
    if not targets:
        print("[!] No valid targets provided.") 
        return
    await scanner.run(targets)
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Interrupted")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        "information"
