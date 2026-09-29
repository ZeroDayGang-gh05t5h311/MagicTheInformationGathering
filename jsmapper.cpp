/* 
sudo apt install libcurl4-openssl-dev libgumbo-dev nlohmann-json3-dev
g++ -std=c++20 -O2 -Wall -Wextra -pthread jsmapper.cpp -lcurl -lgumbo -o jsmapper
*/
#include <curl/curl.h>
#include <gumbo.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <future>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
using json=nlohmann::json;
class Logger{
public:
    static void info(const std::string& msg){
        std::cout<<"[INFO] "<<msg<<std::endl;
    }
    static void warning(const std::string& msg){
        std::cerr<<"[WARNING] "<<msg<<std::endl;
    }
    static void error(const std::string& msg){
        std::cerr<<"[ERROR] "<<msg<<std::endl;
    }
    static void debug(const std::string&){
    }
};
class CurlGlobal{
public:
    CurlGlobal(){
        CURLcode result=curl_global_init(CURL_GLOBAL_DEFAULT);
        if(result!=CURLE_OK){
            throw std::runtime_error("curl init failed");
        }
    }
    ~CurlGlobal(){
        curl_global_cleanup();
    }
};
struct HttpResponse{
    std::string body;
    long status=0;
    std::map<std::string,std::string> headers;
    std::string finalUrl;
};
class HttpClient{
private:
    static size_t writeCallback(void* contents,size_t size,size_t nmemb,void* user){
        size_t total=size*nmemb;
        auto* output=static_cast<std::string*>(user);
        output->append(static_cast<char*>(contents),total);
        return total;
    }
    static size_t headerCallback(char* buffer,size_t size,size_t nmemb,void* user){
        size_t total=size*nmemb;
        auto* headers=static_cast<std::map<std::string,std::string>*>(user);
        std::string line(buffer,total);
        auto pos=line.find(':');
        if(pos!=std::string::npos){
            std::string key=line.substr(0,pos);
            std::string value=line.substr(pos+1);
            while(!value.empty()&&(value.back()=='\n'||value.back()=='\r'||value.back()==' ')){
                value.pop_back();
            }
            (*headers)[key]=value;
        }
        return total;
    }
public:
    HttpResponse get(
        const std::string& url,
        const std::map<std::string,std::string>& headers,
        long timeout=30){
        HttpResponse response;
        CURL* curl=curl_easy_init();
        if(!curl){
            throw std::runtime_error("curl handle failed");
        }
        curl_slist* list=nullptr;
        try{
            curl_easy_setopt(curl,CURLOPT_URL,url.c_str());
            curl_easy_setopt(curl,CURLOPT_TIMEOUT,timeout);
            curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,1L);
            curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,writeCallback);
            curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response.body);
            curl_easy_setopt(curl,CURLOPT_HEADERFUNCTION,headerCallback);
            curl_easy_setopt(curl,CURLOPT_HEADERDATA,&response.headers);
            for(const auto& header:headers){
                std::string value=header.first+": "+header.second;
                list=curl_slist_append(list,value.c_str());
            }
            if(list){
                curl_easy_setopt(curl,CURLOPT_HTTPHEADER,list);
            }
            CURLcode result=curl_easy_perform(curl);
            if(result!=CURLE_OK){
                throw std::runtime_error(curl_easy_strerror(result));
            }
            curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&response.status);
            char* finalUrl=nullptr;
            curl_easy_getinfo(curl,CURLINFO_EFFECTIVE_URL,&finalUrl);
            if(finalUrl){
                response.finalUrl=finalUrl;
            }else{
                response.finalUrl=url;
            }
        }catch(...){
            if(list){
                curl_slist_free_all(list);
            }
            curl_easy_cleanup(curl);
            throw;
        }
        if(list){
            curl_slist_free_all(list);
        }
        curl_easy_cleanup(curl);
        return response;
    }
};
class HtmlParser{
private:
    static void walk(GumboNode* node,std::vector<std::string>& links){
        if(!node){
            return;
        }
        if(node->type==GUMBO_NODE_ELEMENT){
            if(node->v.element.tag==GUMBO_TAG_A){
                GumboAttribute* href=gumbo_get_attribute(
                    &node->v.element.attributes,
                    "href"
                );
                if(href&&href->value){
                    links.push_back(href->value);
                }
            }
            for(unsigned int i=0;i<node->v.element.children.length;i++){
                walk(
                    static_cast<GumboNode*>(node->v.element.children.data[i]),
                    links
                );
            }
        }
    }
public:
    std::vector<std::string> getLinks(const std::string& html){
        std::vector<std::string> links;
        GumboOutput* output=gumbo_parse(html.c_str());
        if(output){
            walk(output->root,links);
            gumbo_destroy_output(&kGumboDefaultOptions,output);
        }
        return links;
    }
};
class PassiveHTMLScanner{
private:
    int threads;
    double delay;
    int retries;
    bool saveHtml;
    int depth;
    std::string outputFile;
    bool stealth;
    bool performance;
    int completed=0;
    int totalTargets=0;
    std::mutex progressMutex;
    std::set<int> rateStatuses;
    std::vector<std::string> rateKeywords;
    std::map<std::string,std::string> defaultHeaders;
    std::map<std::string,std::string> stealthHeaders;
    std::vector<std::string> xssPayloads;
    std::vector<std::pair<std::string,std::regex>> xssPatterns;
    std::vector<std::pair<std::string,std::regex>> domPatterns;
    std::vector<std::pair<std::string,std::regex>> sensitivePatterns;
    HttpClient http;
    HtmlParser parser;
public:
    PassiveHTMLScanner(
        int t,
        double d,
        int r,
        bool save,
        int dep,
        const std::string& out,
        bool st,
        bool perf):
        threads(t),
        delay(d),
        retries(r),
        saveHtml(save),
        depth(dep),
        outputFile(out),
        stealth(st),
        performance(perf){
        rateStatuses={429,403};
        rateKeywords={
            "rate limit",
            "too many requests",
            "access denied",
            "temporarily blocked",
            "captcha"
        };
        defaultHeaders={
            {"User-Agent","Mozilla/5.0 Chrome/120"},
            {"Accept","text/html,application/xhtml+xml"},
            {"Accept-Language","en-US,en;q=0.5"}
        };
        stealthHeaders=defaultHeaders;
        stealthHeaders["User-Agent"]="Mozilla/5.0 Firefox";
        xssPayloads={
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)"
        };
xssPatterns={
            {
                "inline_script",
                std::regex("<script[\\s\\S]*?</script>",std::regex_constants::icase)
            },
            {
                "event_handlers",
                std::regex("on\\w+\\s*=",std::regex_constants::icase)
            },
            {
                "javascript_urls",
                std::regex("javascript:",std::regex_constants::icase)
            },
            {
                "iframe_tags",
                std::regex("<iframe[\\s\\S]*?>",std::regex_constants::icase)
            },
            {
                "eval_usage",
                std::regex("eval\\s*\\(",std::regex_constants::icase)
            }
        };
        domPatterns={
            {
                "innerHTML_usage",
                std::regex("\\.innerHTML\\s*=",std::regex_constants::icase)
            },
            {
                "url_params",
                std::regex("URLSearchParams\\s*\\(",std::regex_constants::icase)
            },
            {
                "location_search",
                std::regex("location\\.search",std::regex_constants::icase)
            },
            {
                "dom_targeting",
                std::regex("getElementById\\s*\\(",std::regex_constants::icase)
            }
        };
        sensitivePatterns={
            {
                "emails",
                std::regex("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+")
            },
            {
                "api_keys",
                std::regex("api[_-]?key\\s*=\\s*[\"']?[A-Za-z0-9_-]{16,}",std::regex_constants::icase)
            },
            {
                "jwt_tokens",
                std::regex("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")
            }
        };
    }
    std::string normalizeUrl(const std::string& url){
        try{
            if(url.empty()){
                return "";
            }
            if(url.rfind("http://",0)!=0&&url.rfind("https://",0)!=0){
                return "https://"+url;
            }
            return url;
        }catch(...){
            return "";
        }
    }
    bool isRateLimited(long status,const std::string& text){
        if(rateStatuses.count(static_cast<int>(status))){
            return true;
        }
        std::string lower=text;
        std::transform(
            lower.begin(),
            lower.end(),
            lower.begin(),
            [](unsigned char c){
                return static_cast<char>(std::tolower(c));
            }
        );
        for(const auto& keyword:rateKeywords){
            if(lower.find(keyword)!=std::string::npos){
                return true;
            }
        }
        return false;
    }
    bool sameDomain(
        const std::string& first,
        const std::string& second){
        auto getHost=[](const std::string& value){
            std::string result=value;
            auto scheme=result.find("://");
            if(scheme!=std::string::npos){
                result=result.substr(scheme+3);
            }
            auto slash=result.find('/');
            if(slash!=std::string::npos){
                result=result.substr(0,slash);
            }
            return result;
        };
        return getHost(first)==getHost(second);
    }
    HttpResponse fetchPage(const std::string& url){
        int attempt=0;
        int backoff=delay>0?static_cast<int>(delay):1;
        while(attempt<=retries){
            try{
                Logger::info(
                    "Fetching: "+
                    url+
                    " attempt "+
                    std::to_string(attempt+1)
                );
                auto headers=
                    stealth?
                    stealthHeaders:
                    defaultHeaders;
                HttpResponse response=
                    http.get(
                        url,
                        headers,
                        30
                    );
                if(isRateLimited(
                    response.status,
                    response.body
                )){
                    Logger::warning(
                        "Rate limited: "+
                        url
                    );
                    std::this_thread::sleep_for(
                        std::chrono::seconds(backoff*2)
                    );
                    backoff*=2;
                    attempt++;
                    continue;
                }
                return response;
            }catch(const std::exception& e){
                Logger::error(
                    std::string("Fetch error: ")+e.what()
                );
            }
            attempt++;
            std::this_thread::sleep_for(
                std::chrono::seconds(backoff)
            );
            backoff*=2;
        }
        return {};
    }
    std::map<std::string,int> scanPatterns(
        const std::string& text,
        const std::vector<std::pair<std::string,std::regex>>& patterns){
        std::map<std::string,int> result;
        for(const auto& pattern:patterns){
            try{
                auto begin=
                    std::sregex_iterator(
                        text.begin(),
                        text.end(),
                        pattern.second
                    );
                auto end=
                    std::sregex_iterator();
                int count=
                    static_cast<int>(
                        std::distance(begin,end)
                    );
                if(count>0){
                    result[pattern.first]=count;
                }
            }catch(const std::exception& e){
                Logger::debug(e.what());
            }
        }
        return result;
    }
std::vector<std::string> extractJsFiles(
        const std::string& html,
        const std::string& baseUrl){
        std::vector<std::string> files;
        try{
            GumboOutput* output=gumbo_parse(html.c_str());
            if(!output){
                return files;
            }
            std::function<void(GumboNode*)> walk;
            walk=[&](GumboNode* node){
                if(!node){
                    return;
                }
                if(node->type==GUMBO_NODE_ELEMENT){
                    if(node->v.element.tag==GUMBO_TAG_SCRIPT){
                        GumboAttribute* src=
                            gumbo_get_attribute(
                                &node->v.element.attributes,
                                "src"
                            );
                        if(src&&src->value){
                            std::string value=src->value;
                            if(value.rfind("http://",0)==0||
                               value.rfind("https://",0)==0){
                                files.push_back(value);
                            }else{
                                if(!value.empty()&&value[0]=='/'){
                                    auto scheme=baseUrl.find("://");
                                    if(scheme!=std::string::npos){
                                        auto slash=
                                            baseUrl.find('/',scheme+3);
                                        if(slash!=std::string::npos){
                                            files.push_back(
                                                baseUrl.substr(0,slash)+value
                                            );
                                        }else{
                                            files.push_back(
                                                baseUrl+value
                                            );
                                        }
                                    }else{
                                        files.push_back(
                                            baseUrl+value
                                        );
                                    }
                                }else{
                                    files.push_back(
                                        baseUrl+"/"+value
                                    );
                                }
                            }
                        }
                    }
                    for(unsigned int i=0;i<node->v.element.children.length;i++){
                        walk(
                            static_cast<GumboNode*>(
                                node->v.element.children.data[i]
                            )
                        );
                    }
                }
            };
            walk(output->root);
            gumbo_destroy_output(
                &kGumboDefaultOptions,
                output
            );
        }catch(const std::exception& e){
            Logger::debug(e.what());
        }
        return files;
    }
    std::vector<std::string> extractEndpoints(
        const std::string& js){
        std::vector<std::regex> patterns{
            std::regex("https?://[^\\s\"']+"),
            std::regex("/[a-zA-Z0-9_/-]+"),
            std::regex("[a-zA-Z0-9_/-]+\\.(php|json|asp|jsp)"),
            std::regex("[\"'](/api/[^\\s\"']+)[\"']"),
            std::regex("[\"'](https?://[^\\s\"']+)[\"']")
        };
        std::set<std::string> endpoints;
        for(const auto& pattern:patterns){
            try{
                auto begin=
                    std::sregex_iterator(
                        js.begin(),
                        js.end(),
                        pattern
                    );
                auto end=
                    std::sregex_iterator();
                for(auto it=begin;it!=end;++it){
                    endpoints.insert(
                        it->str()
                    );
                }
            }catch(const std::exception& e){
                Logger::debug(e.what());
            }
        }
        return std::vector<std::string>(
            endpoints.begin(),
            endpoints.end()
        );
    }
    std::vector<std::string> analyzeJsFiles(
        const std::vector<std::string>& files){
        std::vector<std::future<std::vector<std::string>>> tasks;
        for(const auto& file:files){
            tasks.push_back(
                std::async(
                    std::launch::async,
                    [this,file](){
                        std::vector<std::string> endpoints;
                        try{
                            Logger::info(
                                "Fetching JS: "+
                                file
                            );
                            auto response=
                                http.get(
                                    file,
                                    defaultHeaders,
                                    30
                                );
                            if(response.status==200){
                                endpoints=
                                    extractEndpoints(
                                        response.body
                                    );
                            }
                        }catch(const std::exception& e){
                            Logger::debug(e.what());
                        }
                        return endpoints;
                    }
                )
            );
        }
        std::set<std::string> combined;
        for(auto& task:tasks){
            try{
                auto result=task.get();
                combined.insert(
                    result.begin(),
                    result.end()
                );
            }catch(const std::exception& e){
                Logger::debug(e.what());
            }
        }
        return std::vector<std::string>(
            combined.begin(),
            combined.end()
        );
    }
    std::map<std::string,std::string> extractParameters(
        const std::string& url){
        std::map<std::string,std::string> params;
        try{
            auto question=url.find('?');
            if(question==std::string::npos){
                return params;
            }
            std::string query=
                url.substr(question+1);
            std::stringstream stream(query);
            std::string item;
            while(std::getline(stream,item,'&')){
                auto equal=item.find('=');
                if(equal!=std::string::npos){
                    params[item.substr(0,equal)] =
                        item.substr(equal+1);
                }
            }
        }catch(const std::exception& e){
            Logger::debug(e.what());
        }
        return params;
    }
 std::vector<std::string> testReflection(
        const std::string& url,
        const std::map<std::string,std::string>& params){
        std::vector<std::string> reflected;
        for(const auto& parameter:params){
            try{
                std::string marker="scanner_test_123";
                std::map<std::string,std::string> testParams=params;
                testParams[parameter.first]=marker;
                auto response=
                    http.get(
                        url,
                        defaultHeaders,
                        30
                    );
                if(response.body.find(marker)!=std::string::npos){
                    reflected.push_back(parameter.first);
                }
            }catch(const std::exception& e){
                Logger::debug(e.what());
            }
        }
        return reflected;
    }
    std::map<std::string,std::vector<std::string>> fuzzXss(
        const std::string& url,
        const std::map<std::string,std::string>& params){
        std::map<std::string,std::vector<std::string>> findings;
        for(const auto& parameter:params){
            std::vector<std::string> matched;
            for(const auto& payload:xssPayloads){
                try{
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(200)
                    );
                    std::map<std::string,std::string> testParams=params;
                    testParams[parameter.first]=payload;
                    auto response=
                        http.get(
                            url,
                            defaultHeaders,
                            30
                        );
                    if(response.body.find(payload)!=std::string::npos){
                        matched.push_back(payload);
                    }
                }catch(const std::exception& e){
                    Logger::debug(e.what());
                }
            }
            if(!matched.empty()){
                findings[parameter.first]=matched;
            }
        }
        return findings;
    }
    json processUrl(
        const std::string& url,
        int depthLevel=0){
        json result={
            {"url",url},
            {"final_url",""},
            {"status_code",0},
            {"links",json::array()},
            {"forms",json::array()},
            {"headers",json::object()},
            {"missing_security_headers",json::array()},
            {"xss_patterns",json::object()},
            {"dom_xss_patterns",json::object()},
            {"sensitive_info",json::object()},
            {"js_files",json::array()},
            {"endpoints",json::array()},
            {"parameters",json::object()},
            {"reflected_params",json::array()},
            {"xss_fuzz",json::object()}
        };
        try{
            HttpResponse response=
                fetchPage(url);
            result["final_url"]=
                response.finalUrl;
            result["status_code"]=
                response.status;
            for(const auto& header:response.headers){
                result["headers"][header.first]=header.second;
            }
            std::vector<std::string> securityHeaders={
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "X-Content-Type-Options"
            };
            for(const auto& header:securityHeaders){
                if(response.headers.find(header)==response.headers.end()){
                    result["missing_security_headers"].push_back(header);
                }
            }
            if(!response.body.empty()&&response.body.size()>50){
                if(saveHtml){
                    try{
                        std::string safe=url;
                        for(char& c:safe){
                            if(!std::isalnum(
                                static_cast<unsigned char>(c))){
                                c='_';
                            }
                        }
                        std::ofstream file(
                            "dump_"+safe+".html"
                        );
                        if(file){
                            file<<response.body;
                        }
                    }catch(const std::exception& e){
                        Logger::debug(e.what());
                    }
                }
                auto links=
                    parser.getLinks(
                        response.body
                    );
                for(const auto& link:links){
                    result["links"].push_back({
                        {"title","N/A"},
                        {"url",link}
                    });
                }
                auto xss=
                    scanPatterns(
                        response.body,
                        xssPatterns
                    );
                for(const auto& item:xss){
                    result["xss_patterns"][item.first]=item.second;
                }
                auto dom=
                    scanPatterns(
                        response.body,
                        domPatterns
                    );
                for(const auto& item:dom){
                    result["dom_xss_patterns"][item.first]=item.second;
                }
                auto sensitive=
                    scanPatterns(
                        response.body,
                        sensitivePatterns
                    );
                for(const auto& item:sensitive){
                    result["sensitive_info"][item.first]=item.second;
                }
                auto jsFiles=
                    extractJsFiles(
                        response.body,
                        url
                    );
                for(const auto& js:jsFiles){
                    result["js_files"].push_back(js);
                }
                if(!jsFiles.empty()){
                    auto endpoints=
                        analyzeJsFiles(
                            jsFiles
                        );
                    for(const auto& endpoint:endpoints){
                        result["endpoints"].push_back(endpoint);
                    }
                }
                auto params=
                    extractParameters(url);
                for(const auto& parameter:params){
                    result["parameters"][parameter.first]=parameter.second;
                }
                if(!params.empty()){
                    auto reflected=
                        testReflection(
                            url,
                            params
                        );
                    for(const auto& item:reflected){
                        result["reflected_params"].push_back(item);
                    }
                    auto fuzz=
                        fuzzXss(
                            url,
                            params
                        );
                    for(const auto& item:fuzz){
                        result["xss_fuzz"][item.first]=item.second;
                    }
                }
                if(depthLevel<depth){
                    int count=0;
                    for(const auto& link:links){
                        if(count>=10){
                            break;
                        }
                        if(sameDomain(url,link)){
                            try{
                                processUrl(
                                    link,
                                    depthLevel+1
                                );
                            }catch(const std::exception& e){
                                Logger::debug(e.what());
                            }
                            count++;
                        }
                    }
                }
            }
        }catch(const std::exception& e){
            Logger::error(
                std::string("Processing error: ")+e.what()
            );
        }
        {
            std::lock_guard<std::mutex> lock(
                progressMutex
            );
            completed++;
            double percent=
                totalTargets?
                ((double)completed/(double)totalTargets)*100.0:
                0.0;
            std::cout
            <<"[+] Progress: "
            <<completed
            <<"/"
            <<totalTargets
            <<" ("
            <<std::fixed
            <<std::setprecision(2)
            <<percent
            <<"%)"
            <<std::endl;
        }
        return result;
    }
    void prettyPrint(const json& result){
        try{
            std::cout<<"\n=== "
            <<result["url"]
            <<" ===\n";
            std::cout
            <<"[Status] "
            <<result["status_code"]
            <<" -> "
            <<result["final_url"]
            <<"\n";
            if(!result["links"].empty()){
                std::cout<<"\n[Links]\n";
                for(const auto& link:result["links"]){
                    std::cout
                    <<"- "
                    <<link["url"]
                    <<"\n";
                }
            }
            if(!result["js_files"].empty()){
                std::cout<<"\n[JS Files]\n";
                for(const auto& js:result["js_files"]){
                    std::cout
                    <<"- "
                    <<js
                    <<"\n";
                }
            }
            if(!result["endpoints"].empty()){
                std::cout<<"\n[Endpoints]\n";
                for(const auto& endpoint:result["endpoints"]){
                    std::cout
                    <<"- "
                    <<endpoint
                    <<"\n";
                }
            }
            if(!result["reflected_params"].empty()){
                std::cout<<"\n[Reflected Parameters]\n";
                for(const auto& param:result["reflected_params"]){
                    std::cout
                    <<"- "
                    <<param
                    <<"\n";
                }
            }
            if(!result["xss_fuzz"].empty()){
                std::cout<<"\n[XSS Findings]\n";
                for(auto it=result["xss_fuzz"].begin();
                    it!=result["xss_fuzz"].end();
                    ++it){
                    std::cout
                    <<"- "
                    <<it.key()
                    <<"\n";
                }
            }
        }catch(const std::exception& e){
            Logger::debug(e.what());
        }
    }
    std::vector<json> run(
        const std::vector<std::string>& targets){
        totalTargets=
            static_cast<int>(targets.size());
        std::vector<std::future<json>> tasks;
        std::vector<json> results;
        for(const auto& target:targets){
            tasks.push_back(
                std::async(
                    std::launch::async,
                    [this,target](){
                        return processUrl(target);
                    }
                )
            );
        }
        for(auto& task:tasks){
            try{
                auto result=task.get();
                prettyPrint(result);
                results.push_back(result);
            }catch(const std::exception& e){
                Logger::error(
                    std::string("Task failed: ")+e.what()
                );
            }
        }
        if(!outputFile.empty()){
            try{
                std::ofstream file(outputFile);
                if(!file){
                    throw std::runtime_error(
                        "cannot open output file"
                    );
                }
                file
                <<json(results).dump(2);
            }catch(const std::exception& e){
                Logger::error(
                    std::string("Output error: ")+e.what()
                );
            }
        }
        return results;
    }
};
class CLI{
public:
    static std::map<std::string,std::string> parse(
        int argc,
        char** argv){
        std::map<std::string,std::string> args;
        for(int i=1;i<argc;i++){
            std::string arg=argv[i];
            if(arg=="-u"||arg=="--url"){
                if(i+1<argc){
                    args["url"]=argv[++i];
                }
            }else if(arg=="-l"||arg=="--list"){
                if(i+1<argc){
                    args["list"]=argv[++i];
                }
            }else if(arg=="-t"||arg=="--threads"){
                if(i+1<argc){
                    args["threads"]=argv[++i];
                }
            }else if(arg=="--delay"){
                if(i+1<argc){
                    args["delay"]=argv[++i];
                }
            }else if(arg=="--retries"){
                if(i+1<argc){
                    args["retries"]=argv[++i];
                }
            }else if(arg=="--depth"){
                if(i+1<argc){
                    args["depth"]=argv[++i];
                }
            }else if(arg=="--output"){
                if(i+1<argc){
                    args["output"]=argv[++i];
                }
            }else if(arg=="--save-html"){
                args["save"]="true";
            }else if(arg=="--stealth"){
                args["stealth"]="true";
            }else if(arg=="--performance"){
                args["performance"]="true";
            }else if(arg=="-h"||arg=="--help"){
                args["help"]="true";
            }
        }
        return args;
    }
    static void help(){
        std::cout
        <<"jsmapper.cpp\n"
        <<"Usage:\n"
        <<"-u --url <url>\n"
        <<"-l --list <file>\n"
        <<"-t --threads <number>\n"
        <<"--delay <seconds>\n"
        <<"--retries <number>\n"
        <<"--depth <level>\n"
        <<"--save-html\n"
        <<"--output <file>\n"
        <<"--stealth\n"
        <<"--performance\n";
    }
};
int main(int argc,char** argv){
    try{
        CurlGlobal curl;
        auto args=CLI::parse(argc,argv);
        if(args.count("help")){
            CLI::help();
            return 0;
        }
        int threads=10;
        double delay=0;
        int retries=2;
        int depth=0;
        bool save=false;
        bool stealth=false;
        bool performance=false;
        std::string output;
        if(args.count("threads")){
            threads=std::stoi(args["threads"]);
        }
        if(args.count("delay")){
            delay=std::stod(args["delay"]);
        }
        if(args.count("retries")){
            retries=std::stoi(args["retries"]);
        }
        if(args.count("depth")){
            depth=std::stoi(args["depth"]);
        }
        if(args.count("output")){
            output=args["output"];
        }
        save=args.count("save");
        stealth=args.count("stealth");
        performance=args.count("performance");
        PassiveHTMLScanner scanner(
            threads,
            delay,
            retries,
            save,
            depth,
            output,
            stealth,
            performance
        );
        std::vector<std::string> targets;
        if(args.count("url")){
            auto url=
                scanner.normalizeUrl(
                    args["url"]
                );
            if(!url.empty()){
                targets.push_back(url);
            }
        }
        if(args.count("list")){
            std::ifstream file(
                args["list"]
            );
            if(!file){
                throw std::runtime_error(
                    "cannot read target list"
                );
            }
            std::string line;
            while(std::getline(file,line)){
                auto url=
                    scanner.normalizeUrl(
                        line
                    );
                if(!url.empty()){
                    targets.push_back(url);
                }
            }
        }
        std::set<std::string> unique;
        std::vector<std::string> clean;
        for(const auto& target:targets){
            if(unique.insert(target).second){
                clean.push_back(target);
            }
        }
        if(clean.empty()){
            std::cerr
            <<"No valid targets provided\n";
            return 1;
        }
        scanner.run(clean);
    }catch(const std::exception& e){
        std::cerr
        <<"Fatal error: "
        <<e.what()
        <<std::endl;
        return 1;
    }catch(...){
        std::cerr
        <<"Unknown fatal error"
        <<std::endl;
        return 1;
    }
    return 0;
}
