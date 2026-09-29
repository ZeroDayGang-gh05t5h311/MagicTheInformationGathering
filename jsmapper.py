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
import asyncio
import aiohttp
import re
import argparse
import json
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Dict,List,Any,Optional,Tuple,Set
class PassiveHTMLScanner:
    def __init__(self,threads=10,delay=0.0,retries=2,save_html=False,depth=0,output=None,stealth=False,performance=False):
        self.threads=max(1,threads)
        self.delay=max(0.0,delay)
        self.retries=max(0,retries)
        self.save_html=save_html
        self.depth=max(0,depth)
        self.output=output
        self.stealth=stealth
        self.performance=performance
        self.semaphore=asyncio.Semaphore(self.threads)
        self.lock=asyncio.Lock()
        self.completed=0
        self.total_targets=0
        self.timeout=aiohttp.ClientTimeout(total=30)
        logging.basicConfig(level=logging.INFO,format="[%(levelname)s] %(message)s")
        self.DEFAULT_HEADERS={
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":"en-US,en;q=0.5",
            "Connection":"keep-alive"
        }
        self.STEALTH_HEADERS={
            **self.DEFAULT_HEADERS,
            "User-Agent":"Mozilla/5.0 (Windows NT 6.1; rv:54.0) Gecko/20100101 Firefox/140.1"
        }
        self.XSS_PAYLOADS=[
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)"
        ]
        self.RATE_LIMIT_STATUSES={429,403}
        self.RATE_LIMIT_KEYWORDS=[
            "rate limit",
            "too many requests",
            "access denied",
            "temporarily blocked",
            "captcha"
        ]
        self.XSS_PATTERNS={
            "inline_script":re.compile(r"<script.*?>.*?</script>",re.I|re.S),
            "event_handlers":re.compile(r"on\w+\s*=",re.I),
            "javascript_urls":re.compile(r"javascript:",re.I),
            "iframe_tags":re.compile(r"<iframe.*?>",re.I|re.S),
            "eval_usage":re.compile(r"eval\s*\(",re.I)
        }
        self.DOM_PATTERNS={
            "innerHTML_usage":re.compile(r"\.innerHTML\s*=",re.I),
            "url_params":re.compile(r"URLSearchParams\s*\(",re.I),
            "location_search":re.compile(r"location\.search",re.I),
            "dom_targeting":re.compile(r"getElementById\s*\(",re.I)
        }
        self.SENSITIVE_PATTERNS={
            "emails":re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
            "api_keys":re.compile(r"(?i)(api[\-_]?key\s*=\s*['\"]?[A-Za-z0-9_\-]{16,})"),
            "jwt_tokens":re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
        }
        self.JS_ENDPOINT_PATTERNS=[
            re.compile(r"https?://[^\s\"']+"),
            re.compile(r"/[a-zA-Z0-9_/-]+"),
            re.compile(r"[a-zA-Z0-9_/-]+\.(php|json|asp|jsp)"),
            re.compile(r"['\"](/api/[^\s'\"]+)['\"]"),
            re.compile(r"['\"](https?://[^\s'\"]+)['\"]")
        ]
        self.domain_cache={}
    def normalize_url(self,url:Optional[str])->Optional[str]:
        try:
            if not url:
                return None
            url=url.strip()
            if not url.startswith(("http://","https://")):
                return "https://"+url
            return url
        except Exception as e:
            logging.debug(f"normalize_url error: {e}")
            return None
    def is_rate_limited(self,status:int,text:str)->bool:
        try:
            if status in self.RATE_LIMIT_STATUSES:
                return True
            if text:
                lowered=text.lower()
                return any(k in lowered for k in self.RATE_LIMIT_KEYWORDS)
        except Exception as e:
            logging.debug(f"rate limit check error: {e}")
        return False
    def is_same_domain(self,base:str,target:str)->bool:
        try:
            if base not in self.domain_cache:
                self.domain_cache[base]=urlparse(base).netloc
            if target not in self.domain_cache:
                self.domain_cache[target]=urlparse(target).netloc
            return self.domain_cache[base]==self.domain_cache[target]
        except Exception:
            return False
    async def fetch_page(self,session,url:str)->Tuple:
        attempt=0
        backoff=self.delay or 1.0
        while attempt<=self.retries:
            try:
                if self.delay:
                    await asyncio.sleep(self.delay)
                logging.info(f"[+] Fetching: {url} (attempt {attempt+1})")
                headers=self.STEALTH_HEADERS if self.stealth else self.DEFAULT_HEADERS
                async with self.semaphore:
                    async with session.get(url,timeout=self.timeout,headers=headers) as response:
                        content_type=response.headers.get("Content-Type","")
                        final_url=str(response.url)
                        try:
                            text=await response.text(errors="ignore")
                        except Exception as e:
                            logging.debug(f"text read error: {e}")
                            text=""
                        if self.is_rate_limited(response.status,text):
                            logging.warning(f"[!] Rate limited: {url}")
                            await asyncio.sleep(backoff*2)
                            backoff*=2
                            attempt+=1
                            continue
                        if "html" not in content_type.lower():
                            return None,response.status,dict(response.headers),final_url
                        return text,response.status,dict(response.headers),final_url
            except (aiohttp.ClientError,asyncio.TimeoutError) as e:
                logging.error(f"[!] Fetch error: {e}")
            except Exception as e:
                logging.error(f"[!] Unexpected fetch error: {e}")
            attempt+=1
            await asyncio.sleep(backoff)
            backoff*=2
        return None,None,{},url
    def parse_html(self,html:Optional[str],base_url:str):
        try:
            if not html:
                return [],None,[],[]
            soup=BeautifulSoup(html,"html.parser")
            results=[]
            links=[]
            forms=[]
            for link in soup.find_all("a",href=True):
                try:
                    href=urljoin(base_url,link.get("href",""))
                    if not href or href.startswith(("javascript:","mailto:","#")):
                        continue
                    title=link.get_text(strip=True) or "N/A"
                    results.append({"title":title,"url":href})
                    links.append(href)
                except Exception as e:
                    logging.debug(f"link parse error: {e}")
            for form in soup.find_all("form"):
                try:
                    action=urljoin(base_url,form.get("action") or "")
                    method=(form.get("method") or "get").lower()
                    inputs=[i.get("name") for i in form.find_all("input") if i.get("name")]
                    forms.append({"action":action,"method":method,"inputs":inputs})
                except Exception as e:
                    logging.debug(f"form parse error: {e}")
            return results,soup,links,forms
        except Exception as e:
            logging.error(f"[!] Parsing error: {e}")
            return [],None,[],[]
    def scan_for_xss_patterns(self,html):
        results={}
        if not html:
            return results
        for name,pattern in self.XSS_PATTERNS.items():
            try:
                count=len(pattern.findall(html))
                if count:
                    results[name]=count
            except Exception as e:
                logging.debug(f"xss pattern error: {e}")
        return results
    def scan_for_dom_xss_patterns(self,html):
        results={}
        if not html:
            return results
        for name,pattern in self.DOM_PATTERNS.items():
            try:
                count=len(pattern.findall(html))
                if count:
                    results[name]=count
            except Exception as e:
                logging.debug(f"dom pattern error: {e}")
        return results
    def scan_sensitive_info(self,html):
        results={}
        if not html:
            return results
        for name,pattern in self.SENSITIVE_PATTERNS.items():
            try:
                count=len(pattern.findall(html))
                if count:
                    results[name]=count
            except Exception as e:
                logging.debug(f"sensitive pattern error: {e}")
        return results
    def check_security_headers(self,headers):
        important={
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        }
        try:
            return [header for header in important if header not in headers]
        except Exception as e:
            logging.debug(f"header check error: {e}")
            return []
    def extract_js_files(self,soup,base_url):
        results=[]
        if not soup:
            return results
        try:
            for script in soup.find_all("script",src=True):
                src=script.get("src")
                if src:
                    results.append(urljoin(base_url,src))
        except Exception as e:
            logging.debug(f"js extraction error: {e}")
        return results
    def extract_endpoints_from_js(self,js):
        found=set()
        if not js:
            return []
        for pattern in self.JS_ENDPOINT_PATTERNS:
            try:
                matches=pattern.findall(js)
                for match in matches:
                    if isinstance(match,tuple):
                        found.add(match[0])
                    else:
                        found.add(match)
            except Exception as e:
                logging.debug(f"endpoint extraction error: {e}")
        return list(found)
    async def analyze_js_files(self,session,js_files):
        endpoints=set()
        tasks=[]
        for js_url in js_files:
            tasks.append(self.fetch_js(session,js_url))
        if tasks:
            results=await asyncio.gather(*tasks,return_exceptions=True)
            for item in results:
                if isinstance(item,Exception):
                    continue
                endpoints.update(item)
        return list(endpoints)
    async def fetch_js(self,session,js_url):
        try:
            logging.info(f"[+] Fetching JS: {js_url}")
            async with self.semaphore:
                async with session.get(js_url,headers=self.DEFAULT_HEADERS,timeout=self.timeout) as res:
                    if res.status!=200:
                        return set()
                    text=await res.text(errors="ignore")
                    return set(self.extract_endpoints_from_js(text))
        except Exception as e:
            logging.debug(f"js fetch error: {e}")
            return set()
    def extract_parameters(self,url):
        try:
            parsed=urlparse(url)
            if not parsed.query:
                return {}
            params={}
            for item in parsed.query.split("&"):
                if "=" in item:
                    key,value=item.split("=",1)
                    params[key]=value
            return params
        except Exception as e:
            logging.debug(f"parameter extraction error: {e}")
            return {}
    async def fuzz_xss(self,session,url,params):
        findings={}
        if not params:
            return findings
        tasks=[]
        for param in params:
            tasks.append(self.fuzz_parameter(session,url,params,param))
        results=await asyncio.gather(*tasks,return_exceptions=True)
        for result in results:
            if isinstance(result,tuple):
                key,value=result
                if value:
                    findings[key]=value
        return findings
    async def fuzz_parameter(self,session,url,params,param):
        found=[]
        for payload in self.XSS_PAYLOADS:
            try:
                test_params=params.copy()
                test_params[param]=payload
                await asyncio.sleep(0.2)
                async with self.semaphore:
                    async with session.get(url,params=test_params,headers=self.DEFAULT_HEADERS,timeout=self.timeout) as res:
                        text=await res.text(errors="ignore")
                        if text and payload in text:
                            found.append(payload)
            except Exception as e:
                logging.debug(f"xss fuzz error: {e}")
        return param,found
    async def test_reflection(self,session,url,params):
        reflected=[]
        tasks=[]
        for param in params:
            tasks.append(self.test_parameter_reflection(session,url,params,param))
        results=await asyncio.gather(*tasks,return_exceptions=True)
        for result in results:
            if result:
                reflected.append(result)
        return reflected
    async def test_parameter_reflection(self,session,url,params,param):
        try:
            marker="scanner_test_123"
            test_params=params.copy()
            test_params[param]=marker
            await asyncio.sleep(0.2)
            async with self.semaphore:
                async with session.get(url,params=test_params,headers=self.DEFAULT_HEADERS,timeout=self.timeout) as res:
                    text=await res.text(errors="ignore")
                    if text and marker in text:
                        return param
        except Exception as e:
            logging.debug(f"reflection error: {e}")
        return None
    async def process_url(self,session,url,depth_level=0):
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
            "xss_fuzz":{}
        }
        try:
            if status:
                result["missing_security_headers"]=self.check_security_headers(headers)
            if html and len(html)>50:
                if self.save_html:
                    try:
                        safe_name=re.sub(r"[^a-zA-Z0-9]","_",urlparse(url).netloc)
                        with open(f"dump_{safe_name}.html","w",encoding="utf-8") as file:
                            file.write(html)
                    except Exception as e:
                        logging.debug(f"html save error: {e}")
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
                    recursive_tasks=[
                        self.process_url(session,link,depth_level+1)
                        for link in links[:10]
                        if self.is_same_domain(url,link)
                    ]
                    if recursive_tasks:
                        await asyncio.gather(*recursive_tasks,return_exceptions=True)
        except Exception as e:
            logging.error(f"[!] Processing error for {url}: {e}")
        async with self.lock:
            self.completed+=1
            if self.total_targets:
                percent=(self.completed/self.total_targets)*100
                print(f"[+] Progress: {self.completed}/{self.total_targets} ({percent:.2f}%)")
        return result
    def pretty_print(self,r):
        try:
            print(f"\n=== {r['url']} ===")
            print(f"[Status] {r['status_code']} -> {r['final_url']}")
            if r["links"]:
                print("\n[Links]")
                for item in r["links"]:
                    print(f"- {item['title']} -> {item['url']}")
            if r["forms"]:
                print("\n[Forms]")
                for form in r["forms"]:
                    print(f"- {form}")
            if r["js_files"]:
                print("\n[JS Files]")
                for js in r["js_files"]:
                    print(f"- {js}")
            if r["endpoints"]:
                print("\n[Endpoints]")
                for endpoint in r["endpoints"]:
                    print(f"- {endpoint}")
            if r["parameters"]:
                print("\n[Params]")
                for key,value in r["parameters"].items():
                    print(f"- {key}={value}")
            if r["reflected_params"]:
                print("\n[Reflected]")
                for param in r["reflected_params"]:
                    print(f"- {param}")
            if r["xss_fuzz"]:
                print("\n[XSS Fuzz Findings]")
                for param,payloads in r["xss_fuzz"].items():
                    print(f"- {param}:")
                    for payload in payloads:
                        print(f"  -> {payload}")
        except Exception as e:
            logging.debug(f"print error: {e}")
    async def run(self,targets):
        self.total_targets=len(targets)
        connector=aiohttp.TCPConnector(limit=max(10,self.threads*2),ssl=True)
        async with aiohttp.ClientSession(connector=connector,timeout=self.timeout) as session:
            tasks=[self.process_url(session,url) for url in targets]
            results=await asyncio.gather(*tasks,return_exceptions=True)
        clean_results=[]
        for result in results:
            if isinstance(result,Exception):
                print(f"[!] Task failed: {result}")
                continue
            self.pretty_print(result)
            clean_results.append(result)
        if self.output:
            try:
                with open(self.output,"w",encoding="utf-8") as file:
                    json.dump(clean_results,file,indent=2)
            except Exception as e:
                print(f"[!] Failed writing output: {e}")
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
            with open(args.list,encoding="utf-8") as file:
                targets.extend(line.strip() for line in file if line.strip())
        except Exception as e:
            print(f"[!] Failed to read list: {e}")
            return
    cleaned=[]
    seen=set()
    for target in targets:
        normalized=scanner.normalize_url(target)
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned.append(normalized)
    if not cleaned:
        print("[!] No valid targets provided.")
        return
    await scanner.run(cleaned)
if __name__=="__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[!] Interrupted")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
