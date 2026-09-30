/* g++ -std=c++17 -O2 -Wall -Wextra -pedantic FormMap.cpp -o FormMap -lcurl -lgumbo -pthread
sudo apt install libcurl4-openssl-dev libgumbo-dev nlohmann-json3-dev 
*/
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <functional>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <queue>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>
#include <curl/curl.h>
#include <gumbo.h>
using json=nlohmann::json;
namespace fs=std::filesystem;
const std::string VERSION="3.1";
constexpr size_t MAX_RESPONSE_SIZE=10*1024*1024;
constexpr int MAX_THREADS=50;
constexpr int MAX_REDIRECTS=5;
constexpr int MAX_CRAWL_DEPTH=1;
constexpr int MAX_CRAWL_URLS=500;
constexpr long DEFAULT_TIMEOUT_CONNECT=5;
constexpr long DEFAULT_TIMEOUT_TOTAL=20;
class Logger{
public:
    static bool verbose;
    static void info(const std::string& msg){
        std::cout<<"[INFO] "<<msg<<std::endl;
    }
    static void warning(const std::string& msg){
        std::cerr<<"[WARNING] "<<msg<<std::endl;
    }
    static void error(const std::string& msg){
        std::cerr<<"[ERROR] "<<msg<<std::endl;
    }
    static void debug(const std::string& msg){
        if(verbose){
            std::cerr<<"[DEBUG] "<<msg<<std::endl;
        }
    }
};
bool Logger::verbose=false;
static const std::map<std::string,std::string> DEFAULT_HEADERS={
    {
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) FormMap/3.1"
    },
    {
        "Accept",
        "text/html,application/xhtml+xml"
    },
    {
        "Accept-Language",
        "en-US,en;q=0.9"
    },
    {
        "Accept-Encoding",
        "identity"
    },
    {
        "Connection",
        "keep-alive"
    }
};
struct ScanError{
    std::string category;
    std::string message;
};
struct FormInfo{
    std::string action;
    std::string method;
    std::vector<std::map<std::string,std::string>> inputs;
};
struct BrokenFormReport{
    bool missing_action=false;
    bool missing_inputs=false;
    std::vector<std::string> suspicious_fields;
};
struct PageReport{
    std::string url;
    std::string status="unknown";
    int http_status=0;
    double elapsed=0.0;
    int crawl_depth=0;
    std::vector<FormInfo> forms;
    std::vector<std::string> links;
    std::vector<BrokenFormReport> broken_forms;
    std::vector<ScanError> errors;
};
void to_json(
    json& j,
    const ScanError& e
){
    j={
        {
            "category",
            e.category
        },
        {
            "message",
            e.message
        }
    };
}
void to_json(
    json& j,
    const FormInfo& f
){
    j={
        {
            "action",
            f.action
        },
        {
            "method",
            f.method
        },
        {
            "inputs",
            f.inputs
        }
    };
}
void to_json(
    json& j,
    const BrokenFormReport& b
){
    j={
        {
            "missing_action",
            b.missing_action
        },
        {
            "missing_inputs",
            b.missing_inputs
        },
        {
            "suspicious_fields",
            b.suspicious_fields
        }
    };
}
void to_json(
    json& j,
    const PageReport& p
){
    j={
        {
            "url",
            p.url
        },
        {
            "status",
            p.status
        },
        {
            "http_status",
            p.http_status
        },
        {
            "elapsed",
            p.elapsed
        },
        {
            "crawl_depth",
            p.crawl_depth
        },
        {
            "forms",
            p.forms
        },
        {
            "links",
            p.links
        },
        {
            "broken_forms",
            p.broken_forms
        },
        {
            "errors",
            p.errors
        }
    };
}
std::string safeFilename(
    const std::string& value
){
    try{
        std::string result;
        for(
            unsigned char c:
            value
        ){
            if(
                std::isalnum(c)||
                c=='.'||
                c=='_'||
                c=='-'
            ){
                result+=static_cast<char>(c);
            }else{
                result+='_';
            }
        }
        return result;
    }catch(...){
        return "unknown";
    }
}
std::string normalizeUrl(
    const std::string& input
){
    try{
        if(input.empty()){
            return "";
        }
        std::string url=input;
        auto start=url.find_first_not_of(
            " \t\r\n"
        );
        auto end=url.find_last_not_of(
            " \t\r\n"
        );
        if(
            start==std::string::npos
        ){
            return "";
        }
        url=url.substr(
            start,
            end-start+1
        );
        if(
            url.rfind("http://",0)!=0 &&
            url.rfind("https://",0)!=0
        ){
            url="https://"+url;
        }
        if(
            url.rfind("http://",0)!=0 &&
            url.rfind("https://",0)!=0
        ){
            return "";
        }
        auto scheme=url.find("://");
        if(
            scheme==std::string::npos
        ){
            return "";
        }
        auto hostStart=scheme+3;
        auto slash=url.find(
            '/',
            hostStart
        );
        if(
            slash==std::string::npos
        ){
            slash=url.size();
        }
        if(
            slash<=hostStart
        ){
            return "";
        }
        auto fragment=url.find('#');
        if(
            fragment!=std::string::npos
        ){
            url=url.substr(
                0,
                fragment
            );
        }
        while(
            url.size()>1 &&
            url.back()=='/'
        ){
            url.pop_back();
        }
        return url;
    }catch(const std::exception& e){
        Logger::debug(
            std::string(
                "normalizeUrl: "
            )+
            e.what()
        );
        return "";
    }
}
std::string domainName(
    const std::string& url
){
    try{
        auto pos=url.find("://");
        if(
            pos==std::string::npos
        ){
            return "unknown";
        }
        auto start=pos+3;
        auto end=url.find(
            '/',
            start
        );
        std::string host;
        if(
            end==std::string::npos
        ){
            host=url.substr(start);
        }else{
            host=url.substr(
                start,
                end-start
            );
        }
        return safeFilename(host);
    }catch(...){
        return "unknown";
    }
}
void atomicWrite(
    const fs::path& path,
    const std::string& data
){
    fs::path temp;
    try{
        fs::create_directories(
            path.parent_path()
        );
        temp=path;
        temp+=".tmp";
        {
            std::ofstream file(
                temp,
                std::ios::binary
            );
            if(!file){
                throw std::runtime_error(
                    "cannot create temporary file"
                );
            }
            file<<data;
        }
        fs::rename(
            temp,
            path
        );
    }catch(const std::exception& e){
        Logger::error(
            std::string(
                "Atomic write failed: "
            )+
            e.what()
        );
        try{
            if(
                !temp.empty()&&
                fs::exists(temp)
            ){
                fs::remove(
                    temp
                );
            }
        }catch(...){}
    }
}
struct HttpResponse{
    std::string body;
    long status=0;
    std::map<std::string,std::string> headers;
    std::string contentType;
};
class CurlGlobal{
public:
    CurlGlobal(){
        CURLcode result=
            curl_global_init(
                CURL_GLOBAL_DEFAULT
            );
        if(
            result!=CURLE_OK
        ){
            throw std::runtime_error(
                "curl global init failed"
            );
        }
    }
    ~CurlGlobal(){
        curl_global_cleanup();
    }
};
class HttpClient{
private:
    static size_t writeCallback(
        void* contents,
        size_t size,
        size_t nmemb,
        void* userptr
    ){
        try{
            size_t total=size*nmemb;
            HttpResponse* response=
                static_cast<HttpResponse*>(
                    userptr
                );
            if(
                response->body.size()+total>
                MAX_RESPONSE_SIZE
            ){
                return 0;
            }
            response->body.append(
                static_cast<char*>(contents),
                total
            );
            return total;
        }catch(...){
            return 0;
        }
    }
    static size_t headerCallback(
        char* buffer,
        size_t size,
        size_t nmemb,
        void* userdata
    ){
        try{
            size_t total=size*nmemb;
            auto* headers=
                static_cast<
                    std::map<std::string,std::string>*
                >(userdata);
            std::string line(
                buffer,
                total
            );
            auto pos=line.find(':');
            if(
                pos!=std::string::npos
            ){
                std::string key=
                    line.substr(
                        0,
                        pos
                    );
                std::string value=
                    line.substr(
                        pos+1
                    );
                while(
                    !value.empty()&&
                    std::isspace(
                        static_cast<unsigned char>(
                            value.front()
                        )
                    )
                ){
                    value.erase(
                        value.begin()
                    );
                }
                while(
                    !value.empty()&&
                    (
                        value.back()=='\r'||
                        value.back()=='\n'
                    )
                ){
                    value.pop_back();
                }
                (*headers)[key]=value;
            }
            return total;
        }catch(...){
            return 0;
        }
    }
public:
    HttpResponse get(
        const std::string& url,
        const std::map<std::string,std::string>& headers,
        int retries=3
    ){
        int attempt=0;
        int backoff=1;
        while(
            attempt<=retries
        ){
            CURL* curl=
                curl_easy_init();
            if(
                !curl
            ){
                throw std::runtime_error(
                    "curl handle creation failed"
                );
            }
            struct curl_slist* headerList=nullptr;
            HttpResponse response;
            try{
                for(
                    const auto& header:
                    headers
                ){
                    std::string value=
                        header.first+
                        ": "+
                        header.second;
                    headerList=
                        curl_slist_append(
                            headerList,
                            value.c_str()
                        );
                }
                curl_easy_setopt(
                    curl,
                    CURLOPT_URL,
                    url.c_str()
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_WRITEFUNCTION,
                    writeCallback
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_WRITEDATA,
                    &response
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_HEADERFUNCTION,
                    headerCallback
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_HEADERDATA,
                    &response.headers
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_FOLLOWLOCATION,
                    1L
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_MAXREDIRS,
                    MAX_REDIRECTS
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_CONNECTTIMEOUT,
                    DEFAULT_TIMEOUT_CONNECT
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_TIMEOUT,
                    DEFAULT_TIMEOUT_TOTAL
                );
                curl_easy_setopt(
                    curl,
                    CURLOPT_HTTPHEADER,
                    headerList
                );
                CURLcode result=
                    curl_easy_perform(
                        curl
                    );
                if(
                    result!=CURLE_OK
                ){
                    throw std::runtime_error(
                        curl_easy_strerror(
                            result
                        )
                    );
                }
                curl_easy_getinfo(
                    curl,
                    CURLINFO_RESPONSE_CODE,
                    &response.status
                );
                auto content=
                    response.headers.find(
                        "Content-Type"
                    );
                if(
                    content!=response.headers.end()
                ){
                    response.contentType=
                        content->second;
                }
                if(
                    headerList
                ){
                    curl_slist_free_all(
                        headerList
                    );
                }
                curl_easy_cleanup(
                    curl
                );
                return response;
            }catch(
                const std::exception& e
            ){
                if(
                    headerList
                ){
                    curl_slist_free_all(
                        headerList
                    );
                }
                curl_easy_cleanup(
                    curl
                );
                Logger::warning(
                    std::string(
                        "HTTP attempt failed: "
                    )+
                    e.what()
                );
            }
            attempt++;
            std::this_thread::sleep_for(
                std::chrono::seconds(
                    backoff
                )
            );
            backoff*=2;
        }
        throw std::runtime_error(
            "HTTP request failed after retries"
        );
    }
};
class ThreadPool{
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queueMutex;
    std::condition_variable condition;
    bool stop=false;
public:
    explicit ThreadPool(size_t threads){
        for(size_t i=0;i<threads;i++){
            workers.emplace_back([this](){
                while(true){
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queueMutex);
                        condition.wait(lock,[this](){ return stop||!tasks.empty(); });
                        if(stop&&tasks.empty()) return;
                        task=std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }
    template<class F>
    auto submit(F&& f)->std::future<decltype(f())>{
        using ReturnType=decltype(f());
        auto task=std::make_shared<std::packaged_task<ReturnType()>>(std::forward<F>(f));
        auto result=task->get_future();
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if(stop) throw std::runtime_error("ThreadPool stopped");
            tasks.emplace([task](){(*task)();});
        }
        condition.notify_one();
        return result;
    }
    ~ThreadPool(){
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            stop=true;
        }
        condition.notify_all();
        for(auto& worker:workers){
            if(worker.joinable()) worker.join();
        }
    }
};

class SiteAuditor{
private:
    std::vector<std::string> urls;
    int maxThreads;
    std::string outputMode;
    fs::path outputFile;
    bool saveHtmlEnabled;
    bool followInternalLinks;
    fs::path baseOutput="audit_output";
public:
    SiteAuditor(
        std::vector<std::string> inputUrls,
        int threads,
        std::string mode,
        fs::path file,
        bool saveHtml,
        bool followLinks
    ) :
    urls(std::move(inputUrls)),
    maxThreads(threads),
    outputMode(std::move(mode)),
    outputFile(std::move(file)),
    saveHtmlEnabled(saveHtml),
    followInternalLinks(followLinks)
    {}
private:
    std::vector<PageReport> results;
    std::set<std::string> visited;
    std::mutex resultsMutex;
    std::mutex visitedMutex;
    HttpClient http;
    FormInfo inspectForm(
        GumboNode* form,
        const std::string& url,
        BrokenFormReport& broken
    ){
        FormInfo info;
        try{
            if(
                !form||
                form->type!=GUMBO_NODE_ELEMENT
            ){
                throw std::runtime_error(
                    "invalid form node"
                );
            }
            auto* action=
                gumbo_get_attribute(
                    &form->v.element.attributes,
                    "action"
                );
            auto* method=
                gumbo_get_attribute(
                    &form->v.element.attributes,
                    "method"
                );
            info.method=
                method&&method->value?
                method->value:
                "get";
            std::transform(
                info.method.begin(),
                info.method.end(),
                info.method.begin(),
                [](unsigned char c){
                    return std::tolower(c);
                }
            );
            if(
                action&&action->value
            ){
                std::string value=
                    action->value;
                if(
                    value.rfind(
                        "http",
                        0
                    )==0
                ){
                    info.action=value;
                }else{
                    info.action=
                        url+
                        value;
                }
            }else{
                broken.missing_action=true;
            }
            std::function<void(GumboNode*)> scan;
            scan=
            [&](GumboNode* node){
                if(!node){
                    return;
                }
                if(
                    node->type==
                    GUMBO_NODE_ELEMENT
                ){
                    GumboTag tag=
                        static_cast<GumboTag>(
                            node->v.element.tag
                        );
                    if(
                        tag==GUMBO_TAG_INPUT||
                        tag==GUMBO_TAG_TEXTAREA||
                        tag==GUMBO_TAG_SELECT||
                        tag==GUMBO_TAG_BUTTON
                    ){
                        std::map<std::string,std::string> input;
                        input["element"]=
                            gumbo_normalized_tagname(
                                tag
                            );
                        auto* name=
                            gumbo_get_attribute(
                                &node->v.element.attributes,
                                "name"
                            );
                        auto* type=
                            gumbo_get_attribute(
                                &node->v.element.attributes,
                                "type"
                            );
                        auto* placeholder=
                            gumbo_get_attribute(
                                &node->v.element.attributes,
                                "placeholder"
                            );
                        input["name"]=
                            name&&name->value?
                            name->value:
                            "";
                        input["type"]=
                            type&&type->value?
                            type->value:
                            "";
                        input["placeholder"]=
                            placeholder&&placeholder->value?
                            placeholder->value:
                            "";
                        input["required"]=
                            gumbo_get_attribute(
                                &node->v.element.attributes,
                                "required"
                            )?
                            "true":
                            "false";
                        info.inputs.push_back(
                            input
                        );
                        if(
                            input["name"].empty()
                        ){
                            broken.suspicious_fields.push_back(
                                "missing_input_name"
                            );
                            if(
                                input["type"].empty()||
                                input["type"]=="text"||
                                tag==GUMBO_TAG_TEXTAREA||
                                tag==GUMBO_TAG_SELECT
                            ){
                                broken.suspicious_fields.push_back(
                                    "anonymous_input"
                                );
                            }
                        }
                    }
                    GumboVector* children=
                        &node->v.element.children;
                    for(
                        unsigned int i=0;
                        i<children->length;
                        i++
                    ){
                        scan(
                            static_cast<GumboNode*>(
                                children->data[i]
                            )
                        );
                    }
                }
            };
            scan(
                form
            );
            if(
                info.inputs.empty()
            ){
                broken.missing_inputs=true;
            }
            std::sort(
                broken.suspicious_fields.begin(),
                broken.suspicious_fields.end()
            );
            broken.suspicious_fields.erase(
                std::unique(
                    broken.suspicious_fields.begin(),
                    broken.suspicious_fields.end()
                ),
                broken.suspicious_fields.end()
            );
        }catch(
            const std::exception& e
        ){
            Logger::debug(
                std::string(
                    "Form parsing failed: "
                )+
                e.what()
            );
            broken.suspicious_fields.push_back(
                "form_parse_error"
            );
        }
        return info;
    }
    std::vector<std::string> extractLinks(
        const std::string& html,
        const std::string& url
    ){
        std::set<std::string> unique;
        try{
            GumboOutput* output=
                gumbo_parse(
                    html.c_str()
                );
            if(!output){
                return {};
            }
            std::function<void(GumboNode*)> scan;
            scan=
            [&](GumboNode* node){
                if(!node){
                    return;
                }
                if(
                    node->type==
                    GUMBO_NODE_ELEMENT
                ){
                    if(
                        node->v.element.tag==
                        GUMBO_TAG_A
                    ){
                        auto* href=
                            gumbo_get_attribute(
                                &node->v.element.attributes,
                                "href"
                            );
                        if(
                            href&&
                            href->value
                        ){
                            std::string link=
                                href->value;
                            if(
                                link.rfind(
                                    "http",
                                    0
                                )!=0
                            ){
                                if(
                                    !link.empty()&&
                                    link[0]=='/'
                                ){
                                    auto pos=
                                        url.find(
                                            '/',
                                            8
                                        );
                                    if(
                                        pos!=std::string::npos
                                    ){
                                        link=
                                            url.substr(
                                                0,
                                                pos
                                            )+
                                            link;
                                    }else{
                                        link=
                                            url+
                                            link;
                                    }
                                }else{
                                    link=
                                        url+
                                        "/"+
                                        link;
                                }
                            }
                            auto fragment=
                                link.find('#');
                            if(
                                fragment!=std::string::npos
                            ){
                                link=
                                    link.substr(
                                        0,
                                        fragment
                                    );
                            }
                            if(
                                link.rfind(
                                    url,
                                    0
                                )==0
                            ){
                                while(
                                    link.size()>1&&
                                    link.back()=='/'
                                ){
                                    link.pop_back();
                                }
                                unique.insert(
                                    link
                                );
                            }
                        }
                    }
                    GumboVector* children=
                        &node->v.element.children;
                    for(
                        unsigned int i=0;
                        i<children->length;
                        i++
                    ){
                        scan(
                            static_cast<GumboNode*>(
                                children->data[i]
                            )
                        );
                    }
                }
            };
            scan(
                output->root
            );
            gumbo_destroy_output(
                &kGumboDefaultOptions,
                output
            );
        }catch(
            const std::exception& e
        ){
            Logger::debug(
                e.what()
            );
        }
        return {
            unique.begin(),
            unique.end()
        };
    }
HttpResponse fetch(
        const std::string& url
    ){
        try{
            auto response=
                http.get(
                    url,
                    DEFAULT_HEADERS,
                    3
                );
            if(
                response.body.size()
                >
                MAX_RESPONSE_SIZE
            ){
                throw std::runtime_error(
                    "Response too large"
                );
            }
            if(
                response.contentType.find(
                    "html"
                )
                ==
                std::string::npos
                &&
                !response.contentType.empty()
            ){
                throw std::runtime_error(
                    "Unsupported content type: "+
                    response.contentType
                );
            }
            return response;
        }
        catch(
            const std::exception& e
        ){
            throw std::runtime_error(
                std::string(
                    "Fetch failed: "
                )
                +
                e.what()
            );
        }
    }
    bool saveHtml(
        const fs::path& folder,
        const std::string& name,
        const std::string& data
    ){
        try{
            fs::create_directories(
                folder
            );
            fs::path file=
                folder/
                name;
            std::ofstream output(
                file,
                std::ios::binary
            );
            if(
                !output
            ){
                return false;
            }
            output<<data;
            return true;
        }
        catch(
            const std::exception& e
        ){
            Logger::debug(
                e.what()
            );
            return false;
        }
    }
    PageReport analyze(
        const std::string& url,
        int depth=0
    ){
        auto start=
            std::chrono::steady_clock::now();
        PageReport report;
        report.url=url;
        report.crawl_depth=depth;
        Logger::info(
            "Scanning "+
            url
        );
        try{
            auto response=
                fetch(
                    url
                );
            report.http_status=
                response.status;
            report.status=
                "success";
            std::string safeDomain=
                domainName(
                    url
                );
            auto timestamp=
                std::to_string(
                    std::time(nullptr)
                );
            fs::path folder=
                baseOutput/
                safeDomain/
                timestamp;
            fs::create_directories(
                folder
            );
            if(
                saveHtmlEnabled
            ){
                saveHtml(
                    folder,
                    "index.html",
                    response.body
                );
            }
            auto links=
                extractLinks(
                    response.body,
                    url
                );
            report.links=
                links;
            GumboOutput* output=
                gumbo_parse(
                    response.body.c_str()
                );
            if(
                !output
            ){
                throw std::runtime_error(
                    "HTML parser failed"
                );
            }
            std::function<void(GumboNode*)> forms;
            forms=
            [&](GumboNode* node){
                if(!node){
                    return;
                }
                if(
                    node->type==
                    GUMBO_NODE_ELEMENT
                ){
                    if(
                        node->v.element.tag==
                        GUMBO_TAG_FORM
                    ){
                        BrokenFormReport broken;
                        FormInfo info=
                            inspectForm(
                                node,
                                url,
                                broken
                            );
                        report.forms.push_back(
                            info
                        );
                        if(
                            broken.missing_action
                            ||
                            broken.missing_inputs
                            ||
                            !broken.suspicious_fields.empty()
                        ){
                            report.broken_forms.push_back(
                                broken
                            );
                        }
                    }
                    GumboVector* children=
                        &node->v.element.children;
                    for(
                        unsigned int i=0;
                        i<children->length;
                        i++
                    ){
                        forms(
                            static_cast<GumboNode*>(
                                children->data[i]
                            )
                        );
                    }
                }
            };
            forms(
                output->root
            );
            gumbo_destroy_output(
                &kGumboDefaultOptions,
                output
            );
            if(
                saveHtmlEnabled
            ){
                atomicWrite(
                    folder/
                    "link_map.json",
                    json(
                        report.links
                    ).dump(
                        2
                    )
                );
                for(
                    size_t i=0;
                    i<report.forms.size();
                    i++
                ){
                    atomicWrite(
                        folder/
                        (
                            "form_"+
                            std::to_string(
                                i+1
                            )+
                            ".json"
                        ),
                        json(
                            report.forms[i]
                        ).dump(
                            2
                        )
                    );
                }
            }
        }
        catch(
            const std::runtime_error& e
        ){
            report.status=
                "failed";
            report.errors.push_back(
                {
                    "network",
                    e.what()
                }
            );
            Logger::warning(
                url+
                " failed: "+
                e.what()
            );
        }
        catch(
            const std::exception& e
        ){
            report.status=
                "failed";
            report.errors.push_back(
                {
                    "unexpected",
                    e.what()
                }
            );
            Logger::error(
                e.what()
            );
        }
        auto end=
            std::chrono::steady_clock::now();
        report.elapsed=
            std::chrono::duration<double>(
                end-start
            ).count();
        return report;
    }
    std::vector<PageReport> crawlInternal(
        const std::string& startUrl
    ){
        std::vector<PageReport> reports;
        std::queue<std::pair<std::string,int>> pending;
        pending.push(
            {
                startUrl,
                0
            }
        );
        while(
            !pending.empty()
        ){
            if(
                reports.size()
                >=
                MAX_CRAWL_URLS
            ){
                Logger::warning(
                    "Maximum crawl URL limit reached"
                );
                break;
            }
            auto current=
                pending.front();
            pending.pop();
            std::string url=
                current.first;
            int depth=
                current.second;
            if(
                depth>
                MAX_CRAWL_DEPTH
            ){
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(
                    visitedMutex
                );
                if(
                    visited.count(
                        url
                    )
                ){
                    continue;
                }
                visited.insert(
                    url
                );
            }
            PageReport report=
                analyze(
                    url,
                    depth
                );
            reports.push_back(
                report
            );
            if(
                followInternalLinks
                &&
                report.status=="success"
            ){
                for(
                    const auto& link:
                    report.links
                ){
                    std::lock_guard<std::mutex> lock(
                        visitedMutex
                    );
                    if(
                        !visited.count(
                            link
                        )
                    ){
                        pending.push(
                            {
                                link,
                                depth+1
                            }
                        );
                    }
                }
            }
        }
        return reports;
    }
public:
    void run(){
        try{
            ThreadPool pool(
                maxThreads
            );
            std::vector<std::future<
                std::vector<PageReport>
            >> futures;
            for(
                const auto& url:
                urls
            ){
                if(
                    followInternalLinks
                ){
                    futures.push_back(
                        pool.submit(
                            [this,url](){
                                return crawlInternal(
                                    url
                                );
                            }
                        )
                    );
                }else{
                    futures.push_back(
                        pool.submit(
                            [this,url](){
                                return std::vector<PageReport>{
                                    analyze(
                                        url,
                                        0
                                    )
                                };
                            }
                        )
                    );
                }
            }
            for(
                auto& future:
                futures
            ){
                try{
                    auto result=
                        future.get();
                    std::lock_guard<std::mutex> lock(
                        resultsMutex
                    );
                    results.insert(
                        results.end(),
                        result.begin(),
                        result.end()
                    );
                }
                catch(
                    const std::exception& e
                ){
                    Logger::error(
                        std::string(
                            "Worker failed: "
                        )
                        +
                        e.what()
                    );
                }
            }
            std::sort(
                results.begin(),
                results.end(),
                [](const PageReport& a,
                   const PageReport& b)
                {
                    return a.url < b.url;
                }
            );
        }
        catch(
            const std::exception& e
        ){
            Logger::error(
                std::string(
                    "Fatal auditor failure: "
                )
                +
                e.what()
            );
        }
    }
    const std::vector<PageReport>& getResults() const{
        return results;
    }
    void printResults(){
        for(
            const auto& report:
            results
        ){
            std::cout<<"\n=== "
                     <<report.url
                     <<" ===\n";
            std::cout
                <<"Status: "
                <<report.status
                <<"\n";
            std::cout
                <<"Depth: "
                <<report.crawl_depth
                <<"\n";
            if(
                report.http_status
            ){
                std::cout
                    <<"HTTP: "
                    <<report.http_status
                    <<"\n";
            }
            if(
                report.elapsed>0
            ){
                std::cout
                    <<"Time: "
                    <<report.elapsed
                    <<" seconds\n";
            }
            if(
                !report.errors.empty()
            ){
                for(
                    const auto& error:
                    report.errors
                ){
                    std::cout
                        <<"Error: "
                        <<error.category
                        <<" "
                        <<error.message
                        <<"\n";
                }
            }
            std::cout
                <<"Links: "
                <<report.links.size()
                <<"\n";
            std::cout
                <<"Forms: "
                <<report.forms.size()
                <<"\n";
            std::cout
                <<"Broken forms: "
                <<report.broken_forms.size()
                <<"\n";
            int index=1;
            for(
                const auto& form:
                report.forms
            ){
                std::cout
                    <<"  Form "
                    <<index++
                    <<": "
                    <<form.action
                    <<" ("
                    <<form.method
                    <<") ["
                    <<form.inputs.size()
                    <<" inputs]\n";
            }
        }
    }
    void exportJson(){
        json output=json::array();
        for(
            const auto& report:
            results
        ){
            output.push_back(
                report
            );
        }
        std::string data=
            output.dump(
                2
            );
        if(
            !outputFile.empty()
        ){
            atomicWrite(
                outputFile,
                data
            );
            Logger::info(
                "Saved JSON -> "+
                outputFile.string()
            );
        }else{
            std::cout
                <<data
                <<"\n";
        }
    }
    void output(){
        if(
            outputMode=="json"
        ){
            exportJson();
        }else{
            printResults();
        }
    }
};
struct Arguments{
    std::vector<std::string> urls;
    int threads=5;
    std::string output="terminal";
    fs::path outputFile;
    bool saveHtml=true;
    bool followInternal=false;
};
Arguments parseArguments(
    int argc,
    char** argv
){
    Arguments args;
    for(
        int i=1;
        i<argc;
        i++
    ){
        std::string arg=
            argv[i];
        if(
            arg=="--urls"
            &&
            i+1<argc
        ){
            std::string value=
                argv[++i];
            std::stringstream ss(
                value
            );
            std::string item;
            while(
                std::getline(
                    ss,
                    item,
                    ','
                )
            ){
                if(
                    !item.empty()
                ){
                    args.urls.push_back(
                        item
                    );
                }
            }
        }
        else if(
            arg=="--threads"
            &&
            i+1<argc
        ){
            args.threads=
                std::stoi(
                    argv[++i]
                );
        }
        else if(
            arg=="--output"
            &&
            i+1<argc
        ){
            args.output=
                argv[++i];
        }
        else if(
            arg=="--out-file"
            &&
            i+1<argc
        ){
            args.outputFile=
                argv[++i];
        }
        else if(
            arg=="--no-save-html"
        ){
            args.saveHtml=false;
        }
        else if(
            arg=="--follow-internal-links"
        ){
            args.followInternal=true;
        }
        else if(
            arg=="--help"
            ||
            arg=="-h"
        ){
            std::cout
            <<"FormMap C++\n\n"
            <<"Usage:\n"
            <<"  FormMap --urls URL1,URL2 [options]\n\n"
            <<"Options:\n"
            <<"  --threads N\n"
            <<"  --output terminal|json\n"
            <<"  --out-file FILE\n"
            <<"  --no-save-html\n"
            <<"  --follow-internal-links\n";
            std::exit(
                0
            );
        }
    }
    return args;
}
int main(
    int argc,
    char** argv
){
    try{
        CurlGlobal curl;
        Arguments args=
            parseArguments(
                argc,
                argv
            );
        if(
            args.urls.empty()
        ){
            std::cerr
                <<"No URLs supplied\n";
            return 1;
        }
        std::vector<std::string> clean;
        for(
            const auto& url:
            args.urls
        ){
            auto normalized=
                normalizeUrl(
                    url
                );
            if(
                !normalized.empty()
            ){
                clean.push_back(
                    normalized
                );
            }
        }
        if(
            clean.empty()
        ){
            std::cerr
                <<"No valid URLs supplied\n";
            return 1;
        }
        SiteAuditor auditor(
            clean,
            args.threads,
            args.output,
            args.outputFile,
            args.saveHtml,
            args.followInternal
        );
        auditor.run();
        auditor.output();
    }
    catch(
        const std::exception& e
    ){
        Logger::error(
            std::string(
                "Fatal error: "
            )
            +
            e.what()
        );
        return 1;
    }
    catch(...)
    {
        Logger::error(
            "Unknown fatal error"
        );
        return 1;
    }
    return 0;
}
/*
 g++ -std=c++17 -O2 -Wall -Wextra -pedantic FormMap.cpp -o FormMap -lcurl -lgumbo -pthread
sudo apt install libcurl4-openssl-dev libgumbo-dev nlohmann-json3-dev 
*/
