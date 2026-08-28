#!/usr/bin/python3
"""
jsmapper.py is an asynchronous, object-oriented reconnaissance tool for web applications.
It crawls web pages, extracts links, forms, and JavaScript files, and identifies potential security issues.

Key features include:
- Parsing HTML to enumerate links, forms, and input parameters
- Scanning for XSS patterns, DOM-based XSS risks, and sensitive information
- Extracting endpoints from JavaScript files
- Checking for missing critical security headers
- Optional XSS fuzzing and reflection testing for input parameters
- Multi-threaded asynchronous fetching with rate-limit handling and optional stealth mode
- Optional recursive scanning of internal links to a configurable depth
- JSON output for automated analysis

Note: it's untested.
"""

import asyncio
import aiohttp
import re
import argparse
import json
import logging
import os
import tempfile

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple, Set


class PassiveHTMLScanner:

    def __init__(
        self,
        threads=10,
        delay=0.0,
        retries=2,
        save_html=False,
        depth=0,
        output=None,
        stealth=False,
        performance=False
    ):

        self.threads = max(1, threads)
        self.delay = max(0.0, delay)
        self.retries = max(0, retries)
        self.save_html = save_html
        self.depth = max(0, depth)
        self.output = output
        self.stealth = stealth
        self.performance = performance

        self.max_response_size = 5 * 1024 * 1024
        self.max_backoff = 30

        self.semaphore = asyncio.Semaphore(self.threads)
        self.lock = asyncio.Lock()

        self.completed = 0
        self.total_targets = 0

        logging.basicConfig(
            level=logging.INFO,
            format="[%(levelname)s] %(message)s"
        )

        self.DEFAULT_HEADERS = {
            "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 Chrome/120 Safari/537.36",

            "Accept":
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8",

            "Accept-Language":
                "en-US,en;q=0.5",

            "Connection":
                "keep-alive"
        }

        self.XSS_PAYLOADS = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)"
        ]

        self.RATE_LIMIT_STATUSES = {
            429,
            503
        }

        self.RATE_LIMIT_KEYWORDS = [
            "rate limit",
            "too many requests",
            "temporarily blocked",
            "captcha"
        ]


    def normalize_url(self, url: Optional[str]) -> Optional[str]:

        try:

            if not url:
                return None

            url = url.strip()

            if "\n" in url or "\r" in url:
                return None

            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            parsed = urlparse(url)

            if not parsed.hostname:
                return None

            return url

        except Exception as e:

            logging.debug(
                f"normalize_url error: {e}"
            )

            return None


    def is_rate_limited(
        self,
        status: int,
        text: str
    ) -> bool:

        try:

            if status in self.RATE_LIMIT_STATUSES:
                return True

            if text:

                lowered = text.lower()

                return any(
                    keyword in lowered
                    for keyword in self.RATE_LIMIT_KEYWORDS
                )

        except Exception as e:

            logging.debug(
                f"rate limit check error: {e}"
            )

        return False


    def is_same_domain(
        self,
        base: str,
        target: str
    ) -> bool:

        try:

            base_host = urlparse(base).hostname
            target_host = urlparse(target).hostname

            return (
                base_host is not None
                and base_host == target_host
            )

        except Exception:

            return False


    async def fetch_page(
        self,
        session,
        url: str
    ) -> Tuple:

        attempt = 0
        backoff = self.delay or 1.0

        while attempt <= self.retries:

            try:

                if self.delay:
                    await asyncio.sleep(self.delay)

                logging.info(
                    f"[+] Fetching: {url} "
                    f"(attempt {attempt + 1})"
                )

                headers = dict(self.DEFAULT_HEADERS)

                if self.stealth:

                    headers["User-Agent"] = (
                        "Mozilla/5.0 "
                        "(Windows NT 6.1; rv:54.0) "
                        "Gecko/20100101 Firefox/140.1"
                    )


                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=True
                ) as response:

                    final_url = str(response.url)

                    if not self.is_same_domain(
                        url,
                        final_url
                    ):

                        logging.warning(
                            f"[!] Redirect outside domain: {final_url}"
                        )

                        return None, response.status, dict(response.headers), final_url


                    content_type = response.headers.get(
                        "Content-Type",
                        ""
                    )


                    if "html" not in content_type.lower():

                        return (
                            None,
                            response.status,
                            dict(response.headers),
                            final_url
                        )


                    raw = await response.content.read(
                        self.max_response_size
                    )


                    text = raw.decode(
                        "utf-8",
                        errors="ignore"
                    )


                    if self.is_rate_limited(
                        response.status,
                        text
                    ):

                        logging.warning(
                            f"[!] Rate limited: {url}"
                        )

                        await asyncio.sleep(
                            min(
                                backoff * 2,
                                self.max_backoff
                            )
                        )

                        attempt += 1
                        continue


                    return (
                        text,
                        response.status,
                        dict(response.headers),
                        final_url
                    )


            except Exception as e:

                logging.error(
                    f"[!] Fetch error: {e}"
                )


            attempt += 1

            await asyncio.sleep(
                min(
                    backoff,
                    self.max_backoff
                )
            )

            backoff *= 2


        return None, None, {}, url
    def parse_html(
        self,
        html: Optional[str],
        base_url: str
    ):

        try:

            if not html:
                return [], None, [], []


            soup = BeautifulSoup(
                html,
                "html.parser"
            )

            results = []
            links = []
            forms = []


            for link in soup.find_all(
                "a",
                href=True
            ):

                try:

                    href = urljoin(
                        base_url,
                        link.get("href", "")
                    )

                    if (
                        not href
                        or href.startswith(
                            (
                                "javascript:",
                                "mailto:",
                                "#"
                            )
                        )
                    ):
                        continue


                    title = (
                        link.get_text(
                            strip=True
                        )
                        or "N/A"
                    )


                    results.append(
                        {
                            "title": title,
                            "url": href
                        }
                    )

                    links.append(
                        href
                    )


                except Exception as e:

                    logging.debug(e)



            for form in soup.find_all(
                "form"
            ):

                try:

                    action = urljoin(
                        base_url,
                        form.get("action")
                        or ""
                    )

                    method = (
                        form.get("method")
                        or "get"
                    ).lower()


                    inputs = [
                        i.get("name")
                        for i in form.find_all("input")
                        if i.get("name")
                    ]


                    forms.append(
                        {
                            "action": action,
                            "method": method,
                            "inputs": inputs
                        }
                    )


                except Exception as e:

                    logging.debug(e)


            return (
                results,
                soup,
                links,
                forms
            )


        except Exception as e:

            logging.error(
                f"[!] Parsing error: {e}"
            )

            return [], None, [], []



    def scan_for_xss_patterns(
        self,
        html
    ):

        patterns = {

            "inline_script":
                r"<script\b[^>]*>.*?</script>",

            "event_handlers":
                r"\bon\w+\s*=",

            "javascript_urls":
                r"javascript\s*:",

            "iframe_tags":
                r"<iframe\b",

            "eval_usage":
                r"\beval\s*\("

        }


        results = {}


        for name, pattern in patterns.items():

            try:

                matches = re.findall(
                    pattern,
                    html,
                    re.I | re.S
                )

                if matches:

                    results[name] = len(matches)


            except re.error as e:

                logging.debug(e)


        return results



    def scan_for_dom_xss_patterns(
        self,
        html
    ):

        patterns = {

            "innerHTML_usage":
                r"\.innerHTML\s*=",

            "url_params":
                r"URLSearchParams\s*\(",

            "location_search":
                r"location\.search",

            "dom_targeting":
                r"getElementById\s*\("

        }


        results = {}


        for name, pattern in patterns.items():

            try:

                matches = re.findall(
                    pattern,
                    html,
                    re.I
                )

                if matches:

                    results[name] = len(matches)


            except re.error as e:

                logging.debug(e)


        return results



    def scan_sensitive_info(
        self,
        html
    ):

        patterns = {

            "emails":
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",


            "api_keys":
                r"api[_-]?key\s*=\s*['\"]?[A-Za-z0-9_\-]{16,}",


            "jwt_tokens":
                r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"

        }


        results = {}


        for name, pattern in patterns.items():

            try:

                matches = re.findall(
                    pattern,
                    html,
                    re.I
                )


                if matches:

                    results[name] = len(matches)


            except re.error as e:

                logging.debug(e)


        return results



    def check_security_headers(
        self,
        headers
    ):

        important = [

            "content-security-policy",

            "x-frame-options",

            "x-xss-protection",

            "strict-transport-security",

            "x-content-type-options"

        ]


        try:

            existing = {
                key.lower()
                for key in headers.keys()
            }


            return [
                header
                for header in important
                if header not in existing
            ]


        except Exception as e:

            logging.debug(e)

            return []



    def extract_js_files(
        self,
        soup,
        base_url
    ):

        results = set()


        if not soup:

            return []


        for script in soup.find_all(
            "script",
            src=True
        ):

            try:

                src = script.get(
                    "src"
                )

                if src:

                    results.add(
                        urljoin(
                            base_url,
                            src
                        )
                    )


            except Exception as e:

                logging.debug(e)


        return list(results)



    def extract_endpoints_from_js(
        self,
        js
    ):

        patterns = [

            r"https?://[^\s\"']+",

            r"/[a-zA-Z0-9_\-/]+",

            r"[a-zA-Z0-9_\-/]+\.(php|json|asp|jsp)",

            r"['\"](/api/[^\s'\"]+)['\"]",

            r"['\"](https?://[^\s'\"]+)['\"]"

        ]


        found = set()


        for pattern in patterns:

            try:

                matches = re.findall(
                    pattern,
                    js
                )

                for item in matches:

                    if isinstance(
                        item,
                        tuple
                    ):

                        found.add(
                            item[0]
                        )

                    else:

                        found.add(
                            item
                        )


            except re.error as e:

                logging.debug(e)


        return list(found)
    async def analyze_js_files(self,session,js_files):
        endpoints=set()
        for js_url in js_files:
            try:
                logging.info(f"[+] Fetching JS: {js_url}")
                async with session.get(js_url,headers=dict(self.DEFAULT_HEADERS)) as res:
                    if res.status!=200:
                        continue
                    content=await res.content.read(self.max_response_size)
                    text=content.decode("utf-8",errors="ignore")
                    endpoints.update(self.extract_endpoints_from_js(text))
            except Exception as e:
                logging.debug(e)
        return list(endpoints)
    def extract_parameters(self,url):
        try:
            parsed=urlparse(url)
            params={}
            if parsed.query:
                for item in parsed.query.split("&"):
                    if "=" in item:
                        key,value=item.split("=",1)
                        params[key]=value
            return params
        except Exception as e:
            logging.debug(e)
            return {}
    async def fuzz_xss(self,session,url,params):
        findings={}
        for param in params:
            findings[param]=[]
            for payload in self.XSS_PAYLOADS:
                try:
                    test_params=params.copy()
                    test_params[param]=payload
                    await asyncio.sleep(0.2)
                    async with session.get(url,params=test_params,headers=dict(self.DEFAULT_HEADERS)) as res:
                        if res.status>=400:
                            continue
                        content=await res.content.read(self.max_response_size)
                        text=content.decode("utf-8",errors="ignore")
                        if payload in text:
                            findings[param].append(payload)
                except Exception as e:
                    logging.debug(e)
        return {k:v for k,v in findings.items() if v}
    async def test_reflection(self,session,url,params):
        reflected=[]
        for param in params:
            try:
                marker="scanner_test_123"
                test_params=params.copy()
                test_params[param]=marker
                await asyncio.sleep(0.2)
                async with session.get(url,params=test_params,headers=dict(self.DEFAULT_HEADERS)) as res:
                    if res.status>=400:
                        continue
                    content=await res.content.read(self.max_response_size)
                    text=content.decode("utf-8",errors="ignore")
                    if marker in text:
                        reflected.append(param)
            except Exception as e:
                logging.debug(e)
        return reflected
    async def process_url(self,session,url,depth_level=0):
        async with self.semaphore:
            html,status,headers,final_url=await self.fetch_page(session,url)
        result={
            "url":url,
            "final_url":final_url,
            "status_code":status,
            "links":[],
            "forms":[],
            "headers":headers,
            "missing_security_headers":[],
            "xss_patterns":{},
            "dom_xss_patterns":{},
            "sensitive_info":{},
            "js_files":[],
            "endpoints":[],
            "parameters":{},
            "reflected_params":[],
            "xss_fuzz":[],
            "children":[]
        }
        if status:
            result["missing_security_headers"]=self.check_security_headers(headers)
        if html and len(html)>50:
            if self.save_html:
                try:
                    safe_name=re.sub(r"[^a-zA-Z0-9_.-]","_",urlparse(url).netloc)
                    with open(f"dump_{safe_name}.html","w",encoding="utf-8") as f:
                        f.write(html)
                except Exception as e:
                    logging.debug(e)
            data,soup,links,forms=self.parse_html(html,url)
            result["links"]=data
            result["forms"]=forms
            result["xss_patterns"]=self.scan_for_xss_patterns(html)
            result["dom_xss_patterns"]=self.scan_for_dom_xss_patterns(html)
            result["sensitive_info"]=self.scan_sensitive_info(html)
            js_files=self.extract_js_files(soup,url)
            result["js_files"]=js_files
            if js_files:
                result["endpoints"]=await self.analyze_js_files(session,js_files)
            params=self.extract_parameters(url)
            result["parameters"]=params
            if params:
                result["reflected_params"]=await self.test_reflection(session,url,params)
                result["xss_fuzz"]=await self.fuzz_xss(session,url,params)
            if depth_level<self.depth:
                tasks=[
                    self.process_url(session,link,depth_level+1)
                    for link in links[:10]
                    if self.is_same_domain(url,link)
                ]
                children=await asyncio.gather(*tasks,return_exceptions=True)
                for child in children:
                    if isinstance(child,Exception):
                        continue
                    result["children"].append(child)
        async with self.lock:
            self.completed+=1
            percent=(self.completed/self.total_targets*100) if self.total_targets else 0
            print(f"[+] Progress: {self.completed}/{self.total_targets} ({percent:.2f}%)")
        return result
    def pretty_print(self,r):
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
            for k,v in r["parameters"].items():
                print(f"- {k}={v}")
        if r["reflected_params"]:
            print("\n[Reflected]")
            for p in r["reflected_params"]:
                print(f"- {p}")
        if r["xss_fuzz"]:
            print("\n[XSS Fuzz Findings]")
            for param,payloads in r["xss_fuzz"].items():
                print(f"- {param}:")
                for payload in payloads:
                    print(f"  -> {payload}")
        if r.get("children"):
            print(f"\n[Recursive Results: {len(r['children'])}]")
    async def run(self,targets):
        self.total_targets=len(targets)
        connector=aiohttp.TCPConnector(limit=max(10,self.threads*5),ssl=True)
        timeout=aiohttp.ClientTimeout(connect=5,sock_connect=5,sock_read=15,total=30)
        async with aiohttp.ClientSession(connector=connector,timeout=timeout) as session:
            tasks=[self.process_url(session,url) for url in targets]
            results=await asyncio.gather(*tasks,return_exceptions=True)
        clean_results=[]
        for r in results:
            if isinstance(r,Exception):
                logging.error(f"[!] Task failed: {r}")
                continue
            self.pretty_print(r)
            clean_results.append(r)
        if self.output:
            try:
                directory=os.path.dirname(os.path.abspath(self.output))
                os.makedirs(directory,exist_ok=True)
                fd,temp_path=tempfile.mkstemp(prefix="jsmapper_",suffix=".tmp",dir=directory)
                with os.fdopen(fd,"w",encoding="utf-8") as f:
                    json.dump(clean_results,f,indent=2)
                os.replace(temp_path,self.output)
            except Exception as e:
                logging.error(f"[!] Output error: {e}")
        return clean_results
async def main():
    parser=argparse.ArgumentParser(description="jsmapper.py")
    parser.add_argument("-u","--url")
    parser.add_argument("-l","--list")
    parser.add_argument("-t","--threads",type=int,default=10)
    parser.add_argument("--delay",type=float,default=0.0)
    parser.add_argument("--retries",type=int,default=2)
    parser.add_argument("--save-html",action="store_true")
    parser.add_argument("--depth",type=int,default=0)
    parser.add_argument("--output",help="Save results to JSON")
    parser.add_argument("--stealth",action="store_true",help="Enable stealth mode")
    parser.add_argument("--performance",action="store_true",help="Enable performance mode")
    args=parser.parse_args()
    scanner=PassiveHTMLScanner(
        threads=args.threads,
        delay=args.delay,
        retries=args.retries,
        save_html=args.save_html,
        depth=args.depth,
        output=args.output,
        stealth=args.stealth,
        performance=args.performance
    )
    targets=[]
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list,encoding="utf-8") as f:
                targets.extend([x.strip() for x in f if x.strip()])
        except Exception as e:
            print(f"[!] Failed to read list: {e}")
            return
    targets=list({scanner.normalize_url(t) for t in targets if scanner.normalize_url(t)})
    if not targets:
        print("[!] No valid targets provided.")
        return
    await scanner.run(targets)
if __name__=="__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Interrupted")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
