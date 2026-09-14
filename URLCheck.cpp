/*
Passsive URL Scanner (SQLi && XSS) (POC) 
Very hard to detect things with such a passive scan but...
*/
#include <curl/curl.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>
using namespace std;
class CurlGlobal {
public:
    CurlGlobal(){
        const CURLcode rc=curl_global_init(CURL_GLOBAL_DEFAULT);
        if(rc!=CURLE_OK) throw runtime_error(string("curl_global_init failed: ")+curl_easy_strerror(rc));
    }
    ~CurlGlobal(){curl_global_cleanup();}
    CurlGlobal(const CurlGlobal&)=delete;
    CurlGlobal& operator=(const CurlGlobal&)=delete;
};
class CurlHandle{
    CURL* handle=nullptr;
public:
    CurlHandle():handle(curl_easy_init()){
        if(!handle) throw runtime_error("curl_easy_init failed");
    }
    ~CurlHandle(){if(handle) curl_easy_cleanup(handle);}
    CURL* get() const noexcept{return handle;}
    CurlHandle(const CurlHandle&)=delete;
    CurlHandle& operator=(const CurlHandle&)=delete;
};
struct HttpResponse{
    string body;
    string headers;
    long statusCode=0;
    double totalTime=0.0;
    double connectTime=0.0;
    curl_off_t downloadSize=0;
    string effectiveUrl;
    string contentType;
};
class ResponseCollector{
    string* body;
    size_t maximum;
public:
    ResponseCollector(string* b,size_t m):body(b),maximum(m){}
    static size_t callback(char* ptr,size_t size,size_t nmemb,void* userdata){
        if(!userdata||!ptr) return 0;
        const size_t total=size*nmemb;
        auto* self=static_cast<ResponseCollector*>(userdata);
        if(total>self->maximum||self->body->size()>self->maximum-total) return 0;
        self->body->append(ptr,total);
        return total;
    }
};
class HeaderCollector{
    string* headers;
public:
    explicit HeaderCollector(string* h):headers(h){}
    static size_t callback(char* ptr,size_t size,size_t nmemb,void* userdata){
        if(!userdata||!ptr) return 0;
        const size_t total=size*nmemb;
        auto* self=static_cast<HeaderCollector*>(userdata);
        self->headers->append(ptr,total);
        return total;
    }
};
class SecurityValidator{
public:
    static bool hasControlCharacters(const string& value) noexcept{
        for(unsigned char c:value){
            if(c==0||c=='\r'||c=='\n'||c<0x20||c==0x7f) return true;
        }
        return false;
    }
    static bool validHeader(const string& header) noexcept{
        if(header.empty()||hasControlCharacters(header)) return false;
        const size_t colon=header.find(':');
        if(colon==string::npos||colon==0) return false;
        for(size_t i=0;i<colon;++i){
            const unsigned char c=static_cast<unsigned char>(header[i]);
            if(!(isalnum(c)||c=='-'||c=='_')) return false;
        }
        return true;
    }
    static bool validUrl(const string& url){
        if(url.empty()||url.size()>8192||hasControlCharacters(url)) return false;
        const size_t scheme=url.find("://");
        if(scheme==string::npos) return false;
        string protocol=url.substr(0,scheme);
        transform(protocol.begin(),protocol.end(),protocol.begin(),[](unsigned char c){return static_cast<char>(tolower(c));});
        if(protocol!="http"&&protocol!="https") return false;
        const size_t authorityStart=scheme+3;
        if(authorityStart>=url.size()) return false;
        const size_t authorityEnd=url.find_first_of("/?#",authorityStart);
        const string authority=url.substr(authorityStart,authorityEnd==string::npos?string::npos:authorityEnd-authorityStart);
        if(authority.empty()||authority.find('@')!=string::npos||authority.find('\\')!=string::npos||authority.find(' ')!=string::npos) return false;
        string host=authority;
        if(host.front()=='['){
            const size_t close=host.find(']');
            if(close==string::npos) return false;
            if(close+1<host.size()){
                if(host[close+1]!=':') return false;
                if(close+2>=host.size()) return false;
            }
            return true;
        }
        const size_t colon=host.rfind(':');
        if(colon!=string::npos){
            host.resize(colon);
            if(host.empty()) return false;
        }
        if(host.empty()) return false;
        for(unsigned char c:host){
            if(!(isalnum(c)||c=='.'||c=='-')) return false;
        }
        if(host.front()=='.'||host.back()=='.'||host.front()=='-'||host.back()=='-') return false;
        return true;
    }
};
class HttpClient{
    CurlHandle curl;
    static void check(CURLcode rc,const string& operation){
        if(rc!=CURLE_OK) throw runtime_error(operation+": "+curl_easy_strerror(rc));
    }
public:
    HttpResponse get(const string& url,long timeout,long connectTimeout,bool followRedirects,bool insecure,bool verbose,long maxResponseSize){
        if(!SecurityValidator::validUrl(url)) throw runtime_error("Rejected unsafe or invalid URL; only valid HTTP/HTTPS URLs are permitted");
        if(maxResponseSize<=0) throw runtime_error("Maximum response size must be greater than zero");
        HttpResponse response;
        curl_easy_reset(curl.get());
        const size_t maximum=static_cast<size_t>(maxResponseSize);
        ResponseCollector bodyCollector(&response.body,maximum);
        HeaderCollector headerCollector(&response.headers);
        check(curl_easy_setopt(curl.get(),CURLOPT_URL,url.c_str()),"CURLOPT_URL");
        check(curl_easy_setopt(curl.get(),CURLOPT_WRITEFUNCTION,ResponseCollector::callback),"CURLOPT_WRITEFUNCTION");
        check(curl_easy_setopt(curl.get(),CURLOPT_WRITEDATA,&bodyCollector),"CURLOPT_WRITEDATA");
        check(curl_easy_setopt(curl.get(),CURLOPT_HEADERFUNCTION,HeaderCollector::callback),"CURLOPT_HEADERFUNCTION");
        check(curl_easy_setopt(curl.get(),CURLOPT_HEADERDATA,&headerCollector),"CURLOPT_HEADERDATA");
        check(curl_easy_setopt(curl.get(),CURLOPT_HTTPGET,1L),"CURLOPT_HTTPGET");
        check(curl_easy_setopt(curl.get(),CURLOPT_TIMEOUT,timeout),"CURLOPT_TIMEOUT");
        check(curl_easy_setopt(curl.get(),CURLOPT_CONNECTTIMEOUT,connectTimeout),"CURLOPT_CONNECTTIMEOUT");
        check(curl_easy_setopt(curl.get(),CURLOPT_FOLLOWLOCATION,followRedirects?1L:0L),"CURLOPT_FOLLOWLOCATION");
        check(curl_easy_setopt(curl.get(),CURLOPT_SSL_VERIFYPEER,insecure?0L:1L),"CURLOPT_SSL_VERIFYPEER");
        check(curl_easy_setopt(curl.get(),CURLOPT_SSL_VERIFYHOST,insecure?0L:2L),"CURLOPT_SSL_VERIFYHOST");
        check(curl_easy_setopt(curl.get(),CURLOPT_USERAGENT,"urlcheck/1.0"),"CURLOPT_USERAGENT");
        check(curl_easy_setopt(curl.get(),CURLOPT_ACCEPT_ENCODING,""),"CURLOPT_ACCEPT_ENCODING");
        check(curl_easy_setopt(curl.get(),CURLOPT_PROTOCOLS_STR,"http,https"),"CURLOPT_PROTOCOLS_STR");
        check(curl_easy_setopt(curl.get(),CURLOPT_REDIR_PROTOCOLS_STR,"http,https"),"CURLOPT_REDIR_PROTOCOLS_STR");
        if(verbose) check(curl_easy_setopt(curl.get(),CURLOPT_VERBOSE,1L),"CURLOPT_VERBOSE");
        const CURLcode rc=curl_easy_perform(curl.get());
        if(rc==CURLE_WRITE_ERROR&&response.body.size()>=maximum) throw runtime_error("Response exceeded configured maximum size");
        if(rc!=CURLE_OK) throw runtime_error(string("Request failed: ")+curl_easy_strerror(rc));
        check(curl_easy_getinfo(curl.get(),CURLINFO_RESPONSE_CODE,&response.statusCode),"CURLINFO_RESPONSE_CODE");
        check(curl_easy_getinfo(curl.get(),CURLINFO_TOTAL_TIME,&response.totalTime),"CURLINFO_TOTAL_TIME");
        check(curl_easy_getinfo(curl.get(),CURLINFO_CONNECT_TIME,&response.connectTime),"CURLINFO_CONNECT_TIME");
        check(curl_easy_getinfo(curl.get(),CURLINFO_SIZE_DOWNLOAD_T,&response.downloadSize),"CURLINFO_SIZE_DOWNLOAD_T");
        char* effective=nullptr;
        if(curl_easy_getinfo(curl.get(),CURLINFO_EFFECTIVE_URL,&effective)==CURLE_OK&&effective){
            if(!SecurityValidator::validUrl(effective)) throw runtime_error("Server redirected to a non-HTTP/HTTPS or malformed URL");
            response.effectiveUrl=effective;
        }
        char* contentType=nullptr;
        if(curl_easy_getinfo(curl.get(),CURLINFO_CONTENT_TYPE,&contentType)==CURLE_OK&&contentType) response.contentType=contentType;
        return response;
    }
};
struct Parameter{
    string name;
    string value;
};
class UrlParser{
public:
    static string decode(const string& input){
        string output;
        output.reserve(input.size());
        auto hex=[](char c) noexcept->int{
            if(c>='0'&&c<='9') return c-'0';
            if(c>='a'&&c<='f') return c-'a'+10;
            if(c>='A'&&c<='F') return c-'A'+10;
            return -1;
        };
        for(size_t i=0;i<input.size();++i){
            if(input[i]=='%'&&i+2<input.size()){
                const int a=hex(input[i+1]);
                const int b=hex(input[i+2]);
                if(a>=0&&b>=0){
                    output.push_back(static_cast<char>((a<<4)|b));
                    i+=2;
                    continue;
                }
            }
            if(input[i]=='+') output.push_back(' ');
            else output.push_back(input[i]);
        }
        return output;
    }
    static string encodeMinimal(const string& input){
        ostringstream out;
        out<<hex<<uppercase<<setfill('0');
        for(unsigned char c:input){
            if(isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') out<<static_cast<char>(c);
            else out<<'%'<<setw(2)<<static_cast<int>(c);
        }
        return out.str();
    }
    static vector<Parameter> parameters(const string& url){
        vector<Parameter> result;
        const size_t q=url.find('?');
        if(q==string::npos) return result;
        const size_t end=url.find('#',q);
        const string query=url.substr(q+1,end==string::npos?string::npos:end-q-1);
        stringstream ss(query);
        string item;
        while(getline(ss,item,'&')){
            if(item.empty()) continue;
            const size_t eq=item.find('=');
            Parameter p;
            if(eq==string::npos) p.name=decode(item);
            else{
                p.name=decode(item.substr(0,eq));
                p.value=decode(item.substr(eq+1));
            }
            if(!p.name.empty()) result.push_back(move(p));
        }
        return result;
    }
};
struct Finding{
    string category;
    string severity;
    string parameter;
    string description;
};
class PassiveAnalyzer{
    static string lower(string value){
        transform(value.begin(),value.end(),value.begin(),[](unsigned char c){return static_cast<char>(tolower(c));});
        return value;
    }
    static string compact(string value){
        value=lower(move(value));
        value.erase(remove_if(value.begin(),value.end(),[](unsigned char c){return isspace(c);}),value.end());
        return value;
    }
    static bool containsAny(const string& text,const vector<string>& patterns){
        const string value=lower(text);
        for(const auto& p:patterns) if(value.find(lower(p))!=string::npos) return true;
        return false;
    }
    static bool isInterestingParameter(const string& name){
        static const unordered_set<string> names={
            "q","query","search","searchterm","keyword","term","name","title","text","message","msg",
            "comment","comments","content","body","description","page","url","uri","redirect","return",
            "returnurl","next","target","dest","destination","path","file","filename","id","uid","user",
            "username","email","input","value","sort","order","filter","category","ref","reference",
            "callback","template","view","action","lang","language","link","continue","goto","forward"
        };
        const string n=lower(name);
        if(names.find(n)!=names.end()) return true;
        static const vector<string> fragments={"search","query","url","redirect","return","comment","text","input","id","name","file","path","target","dest"};
        for(const auto& f:fragments) if(n.find(f)!=string::npos) return true;
        return false;
    }
    static string headerValue(const string& headers,const string& wanted){
        const string wantedLower=lower(wanted);
        stringstream ss(headers);
        string line;
        while(getline(ss,line)){
            if(!line.empty()&&line.back()=='\r') line.pop_back();
            const size_t colon=line.find(':');
            if(colon==string::npos) continue;
            const string name=lower(line.substr(0,colon));
            if(name!=wantedLower) continue;
            size_t start=colon+1;
            while(start<line.size()&&isspace(static_cast<unsigned char>(line[start]))) ++start;
            return line.substr(start);
        }
        return "";
    }
    static vector<string> headerValues(const string& headers,const string& wanted){
        vector<string> result;
        const string wantedLower=lower(wanted);
        stringstream ss(headers);
        string line;
        while(getline(ss,line)){
            if(!line.empty()&&line.back()=='\r') line.pop_back();
            const size_t colon=line.find(':');
            if(colon==string::npos) continue;
            const string name=lower(line.substr(0,colon));
            if(name!=wantedLower) continue;
            size_t start=colon+1;
            while(start<line.size()&&isspace(static_cast<unsigned char>(line[start]))) ++start;
            result.push_back(line.substr(start));
        }
        return result;
    }
    static bool looksLikeHtml(const HttpResponse& response){
        const string type=lower(response.contentType);
        if(type.find("text/html")!=string::npos||type.find("application/xhtml")!=string::npos) return true;
        const size_t sampleSize=min<size_t>(4096,response.body.size());
        const string body=lower(response.body.substr(0,sampleSize));
        return body.find("<html")!=string::npos||body.find("<!doctype html")!=string::npos;
    }
    static bool dangerousHtmlContext(const string& context){
        const string c=lower(context);
        static const vector<string> sinks={
            "<script","</script","javascript:","onerror=","onload=","onclick=","onmouseover=",
            "onfocus=","onblur=","onchange=","onsubmit=","oninput=","onkeydown=","onkeyup=",
            "onmouseenter=","onmouseleave=","src=","href=","action=","style=","<iframe",
            "<object","<embed","<svg","<img","<form"
        };
        for(const auto& s:sinks) if(c.find(s)!=string::npos) return true;
        return false;
    }
    static bool htmlEncodedReflection(const string& value,const string& body){
        const string decoded=UrlParser::decode(value);
        if(decoded.empty()) return false;
        const string lowerBody=lower(body);
        string escaped;
        escaped.reserve(decoded.size()*2);
        for(char c:decoded){
            switch(c){
                case '<': escaped+="&lt;"; break;
                case '>': escaped+="&gt;"; break;
                case '"': escaped+="&quot;"; break;
                case '\'': escaped+="&#39;"; break;
                case '&': escaped+="&amp;"; break;
                default: escaped.push_back(c); break;
            }
        }
        return lowerBody.find(lower(escaped))!=string::npos;
    }
    static bool parameterNameLooksDatabaseBacked(const string& name){
        const string n=lower(name);
        static const vector<string> names={
            "id","uid","userid","user_id","item","itemid","product","productid","record","recordid",
            "order","orderid","category","categoryid","page","limit","offset","sort","filter",
            "search","query","term","keyword"
        };
        for(const auto& s:names) if(n==s) return true;
        return false;
    }
public:
    static vector<Finding> analyzeXss(const string&,const HttpResponse& response,const vector<Parameter>& params){
        vector<Finding> findings;
        if(!looksLikeHtml(response)) return findings;
        const string csp=headerValue(response.headers,"content-security-policy");
        const string xfo=headerValue(response.headers,"x-content-type-options");
        const string lowerCsp=lower(csp);
        const bool strongCsp=!csp.empty()&&lowerCsp.find("script-src")!=string::npos;
        for(const auto& p:params){
            if(p.value.empty()) continue;
            vector<pair<size_t,string>> matches;
            matches.reserve(4);
            size_t pos=0;
            while(pos<response.body.size()){
                const size_t a=response.body.find(p.value,pos);
                if(a==string::npos) break;
                matches.emplace_back(a,p.value);
                pos=a+p.value.size();
                if(matches.size()>=20) break;
            }
            const string decoded=UrlParser::decode(p.value);
            if(decoded!=p.value&&!decoded.empty()){
                pos=0;
                while(pos<response.body.size()){
                    const size_t a=response.body.find(decoded,pos);
                    if(a==string::npos) break;
                    matches.emplace_back(a,decoded);
                    pos=a+decoded.size();
                    if(matches.size()>=20) break;
                }
            }
            if(matches.empty()&&htmlEncodedReflection(p.value,response.body)){
                Finding f;
                f.category="XSS";
                f.severity="LOW";
                f.parameter=p.name;
                f.description="Parameter value appears to be reflected after HTML encoding";
                findings.push_back(move(f));
                continue;
            }
            if(!matches.empty()){
                bool dangerous=false;
                bool script=false;
                bool attribute=false;
                bool textOnly=true;
                for(const auto& match:matches){
                    const size_t start=match.first>400?match.first-400:0;
                    const size_t length=min<size_t>(800,response.body.size()-start);
                    const string context=response.body.substr(start,length);
                    const string lc=lower(context);
                    if(lc.find("<script")!=string::npos||lc.find("javascript:")!=string::npos||lc.find("onerror=")!=string::npos||lc.find("onload=")!=string::npos||lc.find("onclick=")!=string::npos||lc.find("onfocus=")!=string::npos||lc.find("oninput=")!=string::npos) script=true;
                    if(lc.find("=\"")!=string::npos||lc.find("='")!=string::npos||lc.find("src=")!=string::npos||lc.find("href=")!=string::npos||lc.find("action=")!=string::npos) attribute=true;
                    if(dangerousHtmlContext(context)) dangerous=true;
                    const size_t relative=match.first-start;
                    const size_t lt=lc.rfind('<',relative);
                    const size_t gt=lc.rfind('>',relative);
                    if(lt!=string::npos&&gt!=string::npos&&lt>gt) textOnly=false;
                }
                Finding f;
                f.category="XSS";
                f.parameter=p.name;
                if(script&&dangerous) f.severity="HIGH";
                else if(dangerous&&attribute) f.severity="MEDIUM";
                else if(!textOnly) f.severity="MEDIUM";
                else f.severity="LOW";
                f.description="Existing parameter value is reflected in the HTML response";
                if(script) f.description+=" near a JavaScript/event-handler context";
                else if(attribute) f.description+=" near an HTML attribute context";
                else if(textOnly) f.description+=" in apparent HTML text";
                if(strongCsp) f.description+="; a CSP script-src policy is present";
                findings.push_back(move(f));
            }else if(isInterestingParameter(p.name)){
                Finding f;
                f.category="XSS";
                f.severity="INFO";
                f.parameter=p.name;
                f.description="Potentially user-controlled parameter was observed but its supplied value was not reflected";
                findings.push_back(move(f));
            }
        }
        if(csp.empty()){
            Finding f;
            f.category="XSS";
            f.severity="INFO";
            f.parameter="";
            f.description="No Content-Security-Policy response header was detected";
            findings.push_back(move(f));
        }
        if(xfo.empty()&&looksLikeHtml(response)){
            Finding f;
            f.category="XSS";
            f.severity="INFO";
            f.parameter="";
            f.description="No X-Content-Type-Options response header was detected";
            findings.push_back(move(f));
        }
        return findings;
    }
    static vector<Finding> analyzeSqli(const string&,const HttpResponse& response,const vector<Parameter>& params){
        vector<Finding> findings;
        static const vector<string> strongDatabaseErrors={
            "you have an error in your sql syntax","warning: mysql_","mysql_fetch_array()","mysql_fetch_assoc()",
            "mysql_num_rows()","mysql_query()","mysqli_query()","mysqli_fetch","pdoexception","sqlstate[",
            "sqlstate:","postgresql query failed","pg_query()","pg_exec()","pg_fetch","ora-00933","ora-00936",
            "ora-00942","ora-01756","ora-01722","oracle error","sqlite error","sqlite3::query","sqlite3::exec",
            "sqlite_exception","unclosed quotation mark after the character string","quoted string not properly terminated",
            "syntax error at or near","microsoft ole db provider for sql server","odbc sql server driver",
            "odbc microsoft access driver","jdbc.sql","com.mysql.jdbc","com.microsoft.sqlserver",
            "org.postgresql.util.psqlexception","org.sqlite","databaseexception","database error"
        };
        static const vector<string> frameworkErrors={
            "sqlalchemy.exc.","django.db.utils.","activerecord::statementinvalid","sequelizedatabaseerror",
            "knex:client","laravel\\database\\queryexception","illuminate\\database\\queryexception",
            "entityframework","hibernateexception","jdbcexception"
        };
        const string bodyLower=lower(response.body);
        bool strong=false;
        string matched;
        for(const auto& e:strongDatabaseErrors){
            if(bodyLower.find(lower(e))!=string::npos){
                strong=true;
                matched=e;
                break;
            }
        }
        if(!strong){
            for(const auto& e:frameworkErrors){
                if(bodyLower.find(lower(e))!=string::npos){
                    strong=true;
                    matched=e;
                    break;
                }
            }
        }
        if(strong){
            Finding f;
            f.category="SQLi";
            f.severity="HIGH";
            f.parameter="";
            f.description="Response exposes a recognizable database/SQL exception signature: "+matched;
            findings.push_back(move(f));
        }
        static const vector<string> genericDatabaseTerms={
            "database connection failed","database unavailable","query failed","query exception","sql exception",
            "db exception","database exception"
        };
        bool generic=false;
        string genericMatched;
        for(const auto& e:genericDatabaseTerms){
            if(bodyLower.find(e)!=string::npos){
                generic=true;
                genericMatched=e;
                break;
            }
        }
        if(generic&&!strong){
            Finding f;
            f.category="SQLi";
            f.severity="MEDIUM";
            f.parameter="";
            f.description="Response contains generic database/query error text: "+genericMatched;
            findings.push_back(move(f));
        }
        static const vector<string> databaseServerHeaders={"x-powered-by","server"};
        for(const auto& header:databaseServerHeaders){
            const string value=headerValue(response.headers,header);
            const string lv=lower(value);
            if(lv.find("php")!=string::npos||lv.find("asp.net")!=string::npos||lv.find("servlet")!=string::npos){
                Finding f;
                f.category="SQLi";
                f.severity="INFO";
                f.parameter="";
                f.description="Application technology is exposed by the "+header+" response header";
                findings.push_back(move(f));
            }
        }
        for(const auto& p:params){
            if(p.value.empty()) continue;
            if(!parameterNameLooksDatabaseBacked(p.name)) continue;
            Finding f;
            f.category="SQLi";
            f.severity="INFO";
            f.parameter=p.name;
            f.description="Parameter name is commonly associated with database-backed application logic; no injection was attempted";
            findings.push_back(move(f));
        }
        if(response.statusCode>=500){
            Finding f;
            f.category="SQLi";
            f.severity="INFO";
            f.parameter="";
            f.description="Server returned an HTTP 5xx response; server-side failure warrants manual investigation";
            findings.push_back(move(f));
        }
        const string powered=headerValue(response.headers,"x-powered-by");
        if(!powered.empty()){
            Finding f;
            f.category="SQLi";
            f.severity="INFO";
            f.parameter="";
            f.description="Application technology disclosed by X-Powered-By: "+powered;
            findings.push_back(move(f));
        }
        return findings;
    }
};
class CommandLine{
public:
    struct Options{
        vector<string> urls;
        long timeout=30;
        long connectTimeout=10;
        long maxResponseSize=10485760;
        bool followRedirects=false;
        bool insecure=false;
        bool verbose=false;
        bool xss=true;
        bool sqli=true;
        string outputFile;
    };
private:
    static bool number(const string& value,long& result){
        if(value.empty()) return false;
        char* end=nullptr;
        errno=0;
        const long v=strtol(value.c_str(),&end,10);
        if(errno!=0||!end||*end!='\0'||v<0) return false;
        result=v;
        return true;
    }
    static void loadUrlsFromFile(const string& filename, Options& o){
        ifstream file(filename);
        if(!file) throw runtime_error("Cannot open URL file: "+filename);
        string line;
        while(getline(file,line)){
            line.erase(remove_if(line.begin(),line.end(),[](unsigned char c){
                return c=='\r'||c=='\n';
            }),line.end());
            if(line.empty()) continue;
            if(!SecurityValidator::validUrl(line))
                throw runtime_error("Invalid or unsafe URL in file: "+line);
            o.urls.push_back(line);
        }
    }
    static string requireValue(int& i,int argc,char** argv,const string& option){
        if(i+1>=argc) throw runtime_error("Missing value for "+option);
        string value=argv[++i];
        if(SecurityValidator::hasControlCharacters(value)) throw runtime_error("Control characters rejected in "+option);
        return value;
    }
public:
    static void help(const char* program){
        cout<<"urlcheck - enhanced passive XSS/SQLi indicator tester\n\n";
        cout<<"Usage:\n";
        cout<<"  "<<program<<" [options] URL [URL ...]\n\n";
        cout<<"Multiple URLs are supported and each URL is tested independently.\n\n";
        cout<<"Options:\n";
        cout<<"  --url URL                 Add a URL to the test list\n";
        cout<<"  --file FILE               Load URLs from a text file (one URL per line)\n";
        cout<<"  --timeout SECONDS         Overall request timeout (default: 30)\n";
        cout<<"  --connect-timeout SECONDS Connection timeout (default: 10)\n";
        cout<<"  --max-size BYTES          Maximum response size (default: 10485760)\n";
        cout<<"  --follow, -L              Follow HTTP redirects\n";
        cout<<"  --insecure, -k            Disable TLS certificate verification\n";
        cout<<"  --verbose, -v             Enable libcurl verbose output\n";
        cout<<"  --xss                     XSS passive analysis only\n";
        cout<<"  --sqli                    SQLi passive analysis only\n";
        cout<<"  --output FILE, -o FILE    Write a text report to FILE\n";
        cout<<"  --help, -h                Show this help\n";
        cout<<"  --version                 Show version\n\n";
        cout<<"Detection:\n";
        cout<<"  XSS analysis checks supplied-value reflection, decoded reflection,\n";
        cout<<"  HTML/attribute/script contexts, event-handler contexts and CSP.\n";
        cout<<"  SQLi analysis checks database/framework exception signatures,\n";
        cout<<"  generic query failures, application technology disclosure and\n";
        cout<<"  parameters commonly associated with database-backed logic.\n\n";
        cout<<"Security:\n";
        cout<<"  Only HTTP and HTTPS URLs are accepted.\n";
        cout<<"  Redirects are restricted to HTTP/HTTPS.\n";
        cout<<"  Control characters are rejected from URLs and option values.\n";
        cout<<"  HTTPS certificate and hostname verification remain enabled by default.\n";
        cout<<"  --insecure disables TLS verification only when explicitly requested.\n\n";
        cout<<"Important:\n";
        cout<<"  No XSS or SQLi payloads are generated or transmitted.\n";
        cout<<"  Detection is passive and cannot prove exploitability.\n";
        cout<<"  Potential findings require manual verification.\n";
    }
    static Options parse(int argc,char** argv){
        Options o;
        bool analysisSpecified=false;
        for(int i=1;i<argc;++i){
            const string arg=argv[i];
            if(arg=="--help"||arg=="-h"){
                help(argv[0]);
                exit(0);
            }
            if(arg=="--version"){
                cout<<"urlcheck 1.2\n";
                exit(0);
            }
            if(arg=="--url"){
                const string value=requireValue(i,argc,argv,arg);
                if(!SecurityValidator::validUrl(value)) throw runtime_error("Invalid or unsafe URL: "+value);
                o.urls.push_back(value);
                continue;
            }
            if(arg=="--file"){
                const string value=requireValue(i,argc,argv,arg);
                loadUrlsFromFile(value,o);
                continue;
            }
            if(arg=="--timeout"){
                const string v=requireValue(i,argc,argv,arg);
                if(!number(v,o.timeout)) throw runtime_error("Invalid timeout: "+v);
                continue;
            }
            if(arg=="--connect-timeout"){
                const string v=requireValue(i,argc,argv,arg);
                if(!number(v,o.connectTimeout)) throw runtime_error("Invalid connect timeout: "+v);
                continue;
            }
            if(arg=="--max-size"){
                const string v=requireValue(i,argc,argv,arg);
                if(!number(v,o.maxResponseSize)||o.maxResponseSize==0) throw runtime_error("Invalid maximum response size: "+v);
                continue;
            }
            if(arg=="--follow"||arg=="-L"){
                o.followRedirects=true;
                continue;
            }
            if(arg=="--insecure"||arg=="-k"){
                o.insecure=true;
                continue;
            }
            if(arg=="--verbose"||arg=="-v"){
                o.verbose=true;
                continue;
            }
            if(arg=="--xss"){
                o.xss=true;
                analysisSpecified=true;
                continue;
            }
            if(arg=="--sqli"){
                o.sqli=true;
                analysisSpecified=true;
                continue;
            }
            if(arg=="--output"||arg=="-o"){
                o.outputFile=requireValue(i,argc,argv,arg);
                continue;
            }
            if(arg=="--"){
                for(++i;i<argc;++i){
                    const string value=argv[i];
                    if(!SecurityValidator::validUrl(value)) throw runtime_error("Invalid or unsafe URL: "+value);
                    o.urls.push_back(value);
                }
                break;
            }
            if(!arg.empty()&&arg.front()=='-') throw runtime_error("Unknown option: "+arg);
            if(!SecurityValidator::validUrl(arg)) throw runtime_error("Invalid or unsafe URL: "+arg);
            o.urls.push_back(arg);
        }
        if(o.urls.empty()) throw runtime_error("No URL supplied. Use --help for usage.");
        if(!analysisSpecified){
            o.xss=true;
            o.sqli=true;
        }
        return o;
    }
};
class Application{
    CommandLine::Options options;
    HttpClient client;
    vector<Finding> allFindings;
    ostream* reportStream=&cout;
    ofstream reportFile;
    void openReport(){
        if(options.outputFile.empty()) return;
        reportFile.open(options.outputFile,ios::out|ios::trunc);
        if(!reportFile) throw runtime_error("Cannot open report file: "+options.outputFile);
        reportStream=&reportFile;
    }
    void process(const string& url,size_t number){
        ostream& out=*reportStream;
        out<<"\n============================================================\n";
        out<<"URL "<<number<<" / "<<options.urls.size()<<"\n";
        out<<"============================================================\n";
        out<<"Target: "<<url<<"\n";
        try{
            const vector<Parameter> params=UrlParser::parameters(url);
            const HttpResponse response=client.get(url,options.timeout,options.connectTimeout,options.followRedirects,options.insecure,options.verbose,options.maxResponseSize);
            out<<"HTTP status: "<<response.statusCode<<"\n";
            out<<"Content-Type: "<<(response.contentType.empty()?"unknown":response.contentType)<<"\n";
            out<<"Response size: "<<response.downloadSize<<" bytes\n";
            out<<"Connect time: "<<fixed<<setprecision(3)<<response.connectTime<<" s\n";
            out<<"Total time: "<<fixed<<setprecision(3)<<response.totalTime<<" s\n";
            if(!response.effectiveUrl.empty()) out<<"Effective URL: "<<response.effectiveUrl<<"\n";
            out<<"Parameters: "<<params.size()<<"\n";
            for(const auto& p:params) out<<"  - "<<p.name<<" = "<<(p.value.empty()?"<empty>":p.value)<<"\n";
            vector<Finding> findings;
            if(options.xss){
                vector<Finding> x=PassiveAnalyzer::analyzeXss(url,response,params);
                findings.insert(findings.end(),make_move_iterator(x.begin()),make_move_iterator(x.end()));
            }
            if(options.sqli){
                vector<Finding> s=PassiveAnalyzer::analyzeSqli(url,response,params);
                findings.insert(findings.end(),make_move_iterator(s.begin()),make_move_iterator(s.end()));
            }
            if(findings.empty()){
                out<<"\nNo passive indicators detected.\n";
            }else{
                out<<"\nFindings:\n";
                for(const auto& f:findings){
                    out<<"  ["<<f.severity<<"] "<<f.category;
                    if(!f.parameter.empty()) out<<" ["<<f.parameter<<"]";
                    out<<": "<<f.description<<"\n";
                }
            }
            bool xss=false;
            bool sqli=false;
            for(auto& f:findings){
                if(f.category=="XSS"&&(f.severity=="HIGH"||f.severity=="MEDIUM")) xss=true;
                if(f.category=="SQLi"&&(f.severity=="HIGH"||f.severity=="MEDIUM")) sqli=true;
                allFindings.push_back(move(f));
            }
            out<<"\nAssessment:\n";
            out<<"  XSS:  "<<(xss?"POTENTIAL INDICATOR":"No strong passive indicator")<<"\n";
            out<<"  SQLi: "<<(sqli?"POTENTIAL INDICATOR":"No strong passive indicator")<<"\n";
            out<<"  NOTE: No XSS or SQLi payloads were sent.\n";
        }catch(const exception& e){
            out<<"ERROR: "<<e.what()<<"\n";
        }
    }
public:
    explicit Application(const CommandLine::Options& o):options(o){}
    int run(){
        openReport();
        for(size_t i=0;i<options.urls.size();++i) process(options.urls[i],i+1);
        ostream& out=*reportStream;
        out<<"\n============================================================\n";
        out<<"OVERALL SUMMARY\n";
        out<<"============================================================\n";
        size_t xss=0;
        size_t sqli=0;
        for(const auto& f:allFindings){
            if(f.category=="XSS"&&(f.severity=="HIGH"||f.severity=="MEDIUM")) ++xss;
            if(f.category=="SQLi"&&(f.severity=="HIGH"||f.severity=="MEDIUM")) ++sqli;
        }
        out<<"URLs tested: "<<options.urls.size()<<"\n";
        out<<"Potential XSS indicators: "<<xss<<"\n";
        out<<"Potential SQLi indicators: "<<sqli<<"\n";
        out<<"Payloads sent: 0\n";
        if(!options.outputFile.empty()) cout<<"Report written to: "<<options.outputFile<<"\n";
        return 0;
    }
};
int main(int argc,char** argv){
    try{
        CurlGlobal curlGlobal;
        const CommandLine::Options options=CommandLine::parse(argc,argv);
        Application application(options);
        return application.run();
    }catch(const exception& e){
        cerr<<"Error: "<<e.what()<<"\n";
        return 1;
    }
}
//g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic urlcheck_0.1.cpp -o urlcheck -lcurl
