// Optimized C++17 version of the provided Python scanner translation (CSV-only).
// Compile: g++ -std=c++17 -O2 -pthread -Wall -Wextra -Wpedantic -o improved_scanner improved_scanner.cpp
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
namespace fs = std::filesystem;
struct Issue {
    std::string file;
    int line;
    std::string pattern;
    std::string match_text;
    std::string snippet;
};
static const std::unordered_map<std::string, std::string> LANG_EXTENSIONS = {
    {".py","python"}, {".js","javascript"}, {".c","c"}, {".cpp","cpp"}, {".cc","cpp"},
    {".h","c"}, {".hpp","cpp"}, {".java","java"}, {".sh","shell"}, {".bash","shell"}
};
static const std::vector<std::string> SQL_INJECTION_PATTERNS = {
    R"((?i)select\s+\*\s+from\s+\w+)",
    R"((?i)insert\s+into\s+\w+\s+\(.*\)\s+values\s+\(.*\))",
    R"((?i)update\s+\w+\s+set\s+.*\s+where\s+.*)",
    R"((?i)drop\s+table\s+\w+)",
    R"((?i)union\s+select\s+.*)",
    R"((?i)and\s+1\s*=\s*1)",
    R"((?i)or\s+1\s*=\s*1)",
    R"((?i)select\s+from\s+information_schema.tables)",
    R"((?i)select\s+from\s+mysql.*user)",
    R"((?i)select\s+from\s+pg_catalog.*pg_user)",
    R"((?i)select\s+from\s+sys\.databases)",
    R"((?i)select\s+from\s+sqlite_master)",
    R"((?i)execute\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+)",
    R"((?i)cursor\.execute\s*\(\s*.*\))",
    R"((?i)prepareStatement\s*\()",
    R"((?i)WHERE\s+1=1\s+--)",
    R"((?i)--\s*$|#\s*$)",
    R"((?i)UNION\s+ALL\s+SELECT)",
    R"((?i)CAST\(.+AS\s+VARCHAR)"
};
static const std::vector<std::string> XSS_PATTERNS = {
    R"((?i)document\.write\s*\()",
    R"((?i)eval\((.*)\)\s*;)",
    R"((?i)innerHTML\s*=\s*)",
    R"((?i)window\.location\s*=)",
    R"((?i)location\.href\s*=)",
    R"((?i)alert\s*\()",
    R"((?i)confirm\s*\()",
    R"((?i)document\.cookie)",
    R"((?i)eval\s*\(\s*["\'].*["\']\s*\))",
    R"((?i)response\.write\()",
    R"((?i)res\.send\()",
    R"((?i)innerText\s*=)",
    R"((?i)document\.createElement\(['\"]script['\"]\))",
    R"((?i)setAttribute\(\s*['\"]on\w+['\"]\s*,)",
    R"((?i)dangerouslySetInnerHTML)",
    R"((?i)style\.cssText\s*=)",
    R"((?i)location\.replace\s*\()",
    R"((?i)res\.end\s*\()"
};
static const std::vector<std::string> COMMAND_INJECTION_PATTERNS = {
    R"((?i)system\s*\()",
    R"((?i)popen\s*\()",
    R"((?i)exec\s*\()",
    R"((?i)Runtime\.getRuntime\s*\(\)\.exec\s*\()",
    R"((?i)subprocess\.(call|Popen)\s*\()",
    R"((?i)child_process\.exec\s*\()",
    R"((?i)nc\s+-e\s+)",
    R"((?i)\$\([^\)]*\))",
    R"((?i)eval\s*\(\s*['\"]\$\([^\)]+\)['\"]\))",
    R"((?i)shell=True)",
    R"((?i)cmd\.exe\s*/c)",
    R"((?i)system\([^,]+;)",
    R"((?i)exec\([^,]+\+)",
    R"((?i)popen\([^,]+\+)",
    R"((?i)ProcessBuilder\s*\(.+builder\.command\()",
    R"((?i)Runtime\.exec\(.+\+)",
    R"((?i)popen2|popen3)",
    R"((?i)subprocess\.(call|check_output)\s*\(.*\+)"
};
static const std::vector<std::string> PATH_TRAVERSAL_PATTERNS = {
    R"(\.\./)",
    R"((\.\./){2,})",
    R"((?i)(c:|/)[^:]+/)",
    R"((?i)file://)",
    R"((?i)open\s*\(\s*\"(\.\./|/)[^\"]+\" )",
    R"((?i)chroot\s*\(\s*\"(\.\./|/)[^\"]+\" )",
    R"((?i)normalizePath\(|path\.normalize\()",
    R"((?i)realpath\(|os\.realpath\()",
    R"(\.\.\\)",
    R"((?i)zipfile\.ZipFile\(|tarfile\.open\()",
    R"((?i)upload_tmp_dir|tmp_name)",
    R"((?i)save_path\s*=)",
    R"((?i)path\.join\([^,]+,\s*\.\.)",
    R"((?i)filename\s*=\s*request\.)",
    R"((?i)Content-Disposition:\s*filename=)"
};
static const std::vector<std::string> INSECURE_DESERIALIZATION_PATTERNS = {
    R"((?i)pickle\.load\s*\()",
    R"((?i)unserialize\s*\()",
    R"((?i)ObjectInputStream\s*\()",
    R"((?i)deserialize\s*\()",
    R"((?i)json\.parse\s*\()",
    R"((?i)XMLDecoder\s*\()",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)yaml\.load\s*\()",
    R"((?i)Marshal\.load\s*\()",
    R"((?i)Marshal\.restore\s*\()",
    R"((?i)eval\(.+base64_decode\()",
    R"((?i)gob\.NewDecoder\(|encoding/gob)",
    R"((?i)serde_json::from_str\()",
    R"((?i)perl\s+Storable::thaw)",
    R"((?i)apache\.commons\.collections)",
    R"((?i)readObject\(|writeReplace\()",
    R"((?i)readObject\s*\()",
    R"((?i)writeObject\s*\()",
    R"((?i)ObjectInputStream\.resolveClass)",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)Gson\.fromJson\s*\()"
};
static const std::vector<std::string> BUFFER_OVERFLOW_PATTERNS = {
    R"((?i)strcpy\s*\(\s*\w+,\s*\w+\))",
    R"((?i)strcat\s*\(\s*\w+,\s*\w+\))",
    R"((?i)gets\s*\()",
    R"((?i)scanf\s*\()",
    R"((?i)memcpy\s*\()",
    R"((?i)fgets\s*\()",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)yaml\.load\s*\()",
    R"((?i)Marshal\.load\s*\()",
    R"((?i)Marshal\.restore\s*\()",
    R"((?i)eval\(.+base64_decode\()",
    R"((?i)gob\.NewDecoder\(|encoding/gob)",
    R"((?i)serde_json::from_str\()",
    R"((?i)perl\s+Storable::thaw)",
    R"((?i)apache\.commons\.collections)",
    R"((?i)readObject\(|writeReplace\()",
    R"((?i)readObject\s*\()",
    R"((?i)writeObject\s*\()",
    R"((?i)ObjectInputStream\.resolveClass)",
    R"((?i)XStream\.fromXML\s*\()",
    R"((?i)Gson\.fromJson\s*\()",
    R"((?i)malloc\s*\(|(?i)calloc\s*\()",
    R"((?i)stack_exec|mprotect\s*\()",
    R"((?i)memset\(.+0x00)"
};
static const std::vector<std::string> CSRF_PATTERNS = {
    R"((?i)document\.location\.href\s*=\s*['\"]\S+['\"])",
    R"((?i)form\s+action\s*=\s*['\"]\S+['\"])",
    R"((?i)window\.location\s*=\s*['\"]\S+['\"])",
    R"((?i)\$\('[^']+'\)\.submit\s*\()",
    R"((?i)post\s+method\s*=\s*['\"]\S+['\"])",
    R"((?i)input\s+type\s*=\s*['\"]hidden['\"]\s+name\s*=\s*['\"]csrf)",
    R"((?i)X-CSRF-Token)",
    R"((?i)SameSite=None)",
    R"((?i)document\.forms\[[0-9]+\]\.submit)",
    R"((?i)action\s*=\s*\"/external)",
    R"((?i)autofill)"
};
static const std::vector<std::string> IMPROPER_AUTHENTICATION_PATTERNS = {
    R"((?i)session_id\s*=\s*['\"][a-zA-Z0-9]{32}['\"])",
    R"((?i)request\.cookies\s*\['session_id'\])",
    R"((?i)Authorization\s*:\s*['\"]Bearer\s+[A-Za-z0-9\-_]+['\"])",
    R"((?i)auth_token\s*=\s*['\"][A-Za-z0-9\-_]+['\"])",
    R"((?i)request\.headers\s*\['Authorization'\])",
    R"((?i)password\s*=\s*['\"][^'\"]{1,}['\"])",
    R"((?i)api_key\s*=\s*['\"][A-Za-z0-9\-_]+['\"])",
    R"((?i)hardcoded_secret|hardcoded_key|private_key\s*=)",
    R"((?i)Basic\s+[A-Za-z0-9=]+)",
    R"((?i)set_cookie\(|cookie\.set\()",
    R"((?i)session\.(start|destroy))",
    R"((?i)bcrypt\.hashpw\(|password_hash\()",
    R"((?i)compare_digest\(|hmac\.compare_digest\()",
    R"((?i)token_expiry|exp\s*:)",
    R"((?i)Authorization\s*:\s*Bearer)"
};
static const std::vector<std::string> INSECURE_API_PATTERNS = {
    R"((?i)/api/v[0-9]+/users)",
    R"((?i)/api/v[0-9]+/admin)",
    R"((?i)/api/v[0-9]+/token)",
    R"((?i)/api/v[0-9]+/password)",
    R"((?i)/api/v[0-9]+/login)",
    R"((?i)/internal/|/private/|/debug/)",
    R"((?i)swagger.json|api-docs|/v2/api-docs)",
    R"((?i)X-Forwarded-For)",
    R"((?i)introspect|.well-known/openid-configuration)",
    R"((?i)graphql)",
    R"((?i)rate_limit|throttle)",
    R"((?i)Authorization\s*:\s*Bearer # token leakage in logs/header)"
};
static const std::vector<std::string> INSECURE_CRYPTOGRAPHIC_PATTERNS = {
    R"((?i)MD5\s*\()",
    R"((?i)SHA1\s*\()",
    R"((?i)base64\s*\()",
    R"((?i)plaintext\s*=\s*['\"][a-zA-Z0-9]+['\"])",
    R"((?i)AES-ECB|AES128-ECB|ECB_MODE)",
    R"((?i)openssl\s+enc\s+-aes-128-cbc)",
    R"((?i)RSA_padding\(|RSA_NO_PADDING)",
    R"((?i)SSLv3|ssl3)",
    R"((?i)RC4|DES|3DES|EXPORT)",
    R"((?i)hardcoded_key|hardcoded_password|private_key.*=)",
    R"((?i)PBKDF2|bcrypt|scrypt)",
    R"((?i)iteration_count\s*=\s*\d{1,4})",
    R"((?i)random\.random\(|Math\.random\()",
    R"((?i)secure_random|SystemRandom)",
    R"((?i)HMAC-SHA1)",
    R"((?i)cryptography\.hazmat|from\s+Crypto\.)"
};
static const std::vector<std::string> RACE_CONDITION_PATTERNS = {
    R"((?i)pthread_mutex_lock\s*\()",
    R"((?i)pthread_mutex_unlock\s*\()",
    R"((?i)fsync\s*\()",
    R"((?i)wait\s*\()",
    R"((?i)open\([^,]+,\s*O_CREAT\|O_EXCL)",
    R"((?i)rename\()",
    R"((?i)stat\(|lstat\()",
    R"((?i)mktemp\s*\()",
    R"((?i)lockf\s*\()",
    R"((?i)sem_wait|sem_post)",
    R"((?i)volatile\s+)",
    R"((?i)atomic_compare_exchange)",
    R"((?i)nsync|pthread_create)"
};
static const std::vector<std::string> PRIVILEGE_ESCALATION_PATTERNS = {
    R"((?i)sudo\s+)",
    R"((?i)chmod\s+777\s+)",
    R"((?i)chown\s+)",
    R"((?i)setuid\(|setgid\(|seteuid\(|setegid\()",
    R"((?i)cap_set_file|cap_get_proc)",
    R"((?i)passwd\s+)",
    R"((?i)/etc/shadow|/etc/passwd)",
    R"((?i)su\s+-)",
    R"((?i)mount\s+-o\s+)",
    R"((?i)docker\s+run\s+--privileged)",
    R"((?i)iptables\s+)",
    R"((?i)chroot\s*\()"
};
static const std::unordered_map<std::string, std::vector<std::string>> LANGUAGE_PATTERNS = {
    {"python", [](){
        std::vector<std::string> v;
        v.reserve(SQL_INJECTION_PATTERNS.size() + XSS_PATTERNS.size() + COMMAND_INJECTION_PATTERNS.size() + INSECURE_CRYPTOGRAPHIC_PATTERNS.size());
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), XSS_PATTERNS.begin(), XSS_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), INSECURE_CRYPTOGRAPHIC_PATTERNS.begin(), INSECURE_CRYPTOGRAPHIC_PATTERNS.end());
        return v;
    }()},
    {"javascript", [](){
        std::vector<std::string> v;
        v.reserve(XSS_PATTERNS.size() + COMMAND_INJECTION_PATTERNS.size() + INSECURE_API_PATTERNS.size());
        v.insert(v.end(), XSS_PATTERNS.begin(), XSS_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), INSECURE_API_PATTERNS.begin(), INSECURE_API_PATTERNS.end());
        return v;
    }()},
    {"c", [](){
        std::vector<std::string> v;
        v.reserve(SQL_INJECTION_PATTERNS.size() + COMMAND_INJECTION_PATTERNS.size() + BUFFER_OVERFLOW_PATTERNS.size() + PATH_TRAVERSAL_PATTERNS.size());
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), BUFFER_OVERFLOW_PATTERNS.begin(), BUFFER_OVERFLOW_PATTERNS.end());
        v.insert(v.end(), PATH_TRAVERSAL_PATTERNS.begin(), PATH_TRAVERSAL_PATTERNS.end());
        return v;
    }()},
    {"cpp", [](){
        std::vector<std::string> v;
        v.reserve(SQL_INJECTION_PATTERNS.size() + COMMAND_INJECTION_PATTERNS.size() + BUFFER_OVERFLOW_PATTERNS.size() + PATH_TRAVERSAL_PATTERNS.size());
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), BUFFER_OVERFLOW_PATTERNS.begin(), BUFFER_OVERFLOW_PATTERNS.end());
        v.insert(v.end(), PATH_TRAVERSAL_PATTERNS.begin(), PATH_TRAVERSAL_PATTERNS.end());
        return v;
    }()},
    {"java", [](){
        std::vector<std::string> v;
        v.reserve(SQL_INJECTION_PATTERNS.size() + INSECURE_DESERIALIZATION_PATTERNS.size() + IMPROPER_AUTHENTICATION_PATTERNS.size());
        v.insert(v.end(), SQL_INJECTION_PATTERNS.begin(), SQL_INJECTION_PATTERNS.end());
        v.insert(v.end(), INSECURE_DESERIALIZATION_PATTERNS.begin(), INSECURE_DESERIALIZATION_PATTERNS.end());
        v.insert(v.end(), IMPROPER_AUTHENTICATION_PATTERNS.begin(), IMPROPER_AUTHENTICATION_PATTERNS.end());
        return v;
    }()},
    {"shell", [](){
        std::vector<std::string> v;
        v.reserve(COMMAND_INJECTION_PATTERNS.size() + PRIVILEGE_ESCALATION_PATTERNS.size());
        v.insert(v.end(), COMMAND_INJECTION_PATTERNS.begin(), COMMAND_INJECTION_PATTERNS.end());
        v.insert(v.end(), PRIVILEGE_ESCALATION_PATTERNS.begin(), PRIVILEGE_ESCALATION_PATTERNS.end());
        return v;
    }()}
};
static const std::set<std::string> DEFAULT_IGNORED_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv", ".idea", ".gradle"
};
static std::string normalize_regex_pattern(const std::string& pattern) {
    std::string normalized;
    normalized.reserve(pattern.size());
    for (std::size_t i = 0; i < pattern.size();) {
        if (i + 3 < pattern.size() && pattern[i] == '(' && pattern[i + 1] == '?' &&
            pattern[i + 2] == 'i' && pattern[i + 3] == ')') {
            i += 4;
            continue;
        }
        normalized.push_back(pattern[i++]);
    }
    return normalized;
}
static std::string escape_regex_literal(const std::string& pattern) {
    std::string escaped;
    escaped.reserve(pattern.size() * 2);
    for (unsigned char ch : pattern) {
        if (std::ispunct(ch))
            escaped.push_back('\\');
        escaped.push_back(static_cast<char>(ch));
    }
    return escaped;
}
static bool compile_regex(const std::string& pattern, std::regex& output) {
    const std::string normalized = normalize_regex_pattern(pattern);
    try {
        output = std::regex(
            normalized,
            std::regex_constants::ECMAScript |
            std::regex_constants::icase);
        return true;
    } catch (const std::regex_error&) {
        try {
            output = std::regex(
                escape_regex_literal(normalized),
                std::regex_constants::ECMAScript |
                std::regex_constants::icase);
            return true;
        } catch (...) {
            return false;
        }
    }
}
std::map<std::string, std::vector<std::regex>> compile_patterns_map(
    const std::map<std::string, std::vector<std::string>>& src) {
    std::map<std::string, std::vector<std::regex>> out;
    for (const auto& [key, vec] : src) {
        std::vector<std::regex> compiled;
        compiled.reserve(vec.size());
        for (const auto& pattern : vec) {
            std::regex re;
            if (compile_regex(pattern, re))
                compiled.emplace_back(std::move(re));
        }
        out.emplace(key, std::move(compiled));
    }
    return out;
}
std::vector<std::regex> compile_patterns_vector(
    const std::vector<std::string>& vec) {
    std::vector<std::regex> compiled;
    compiled.reserve(vec.size());
    for (const auto& pattern : vec) {
        std::regex re;
        if (compile_regex(pattern, re))
            compiled.emplace_back(std::move(re));
    }
    return compiled;
}
bool is_text_file(
    const fs::path& path,
    std::size_t max_bytes = 2048,
    double printable_threshold = 0.75) {
    std::ifstream fh(path, std::ios::binary);
    if (!fh) return false;
    std::vector<char> chunk;
    chunk.resize(max_bytes);
    fh.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
    const std::streamsize bytes_read = fh.gcount();
    if (bytes_read <= 0) return true;
    chunk.resize(static_cast<std::size_t>(bytes_read));
    static const std::string printable_chars =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\v\f";
    std::size_t printable_count = 0;
    for (unsigned char c : chunk) {
        if (c == '\0') return false;
        if (printable_chars.find(static_cast<char>(c)) != std::string::npos)
            ++printable_count;
    }
    const double ratio =
        static_cast<double>(printable_count) /
        static_cast<double>(chunk.size());
    return ratio >= printable_threshold;
}
std::string remove_comments_and_strings_preserve_offsets(
    const std::string& text,
    const std::string& lang) {
    std::string chars = text;
    std::regex pattern;
    if (lang == "python") {
        pattern = std::regex(
            R"(('''[\s\S]*?'''|"""[\s\S]*?"""|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|#.*?$))",
            std::regex_constants::ECMAScript);
    } else if (lang == "javascript") {
        pattern = std::regex(
            R"((`(?:\\.|[^`\\\n])*`|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|//.*?$|/\*[\s\S]*?\*/))",
            std::regex_constants::ECMAScript);
    } else if (lang == "shell") {
        pattern = std::regex(
            R"((`(?:\\.|[^`\\\n])*`|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|#.*?$))",
            std::regex_constants::ECMAScript);
    } else if (lang == "c" || lang == "cpp" || lang == "java") {
        pattern = std::regex(
            R"((\'(?:\\.|[^'\\\n])*\'|"(?:\\.|[^"\\\n])*"|//.*?$|/\*[\s\S]*?\*/))",
            std::regex_constants::ECMAScript);
    } else {
        pattern = std::regex(
            R"(('(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|#.*?$))",
            std::regex_constants::ECMAScript);
    }
    try {
        std::sregex_iterator it(text.begin(), text.end(), pattern);
        const std::sregex_iterator end;
        for (; it != end; ++it) {
            const auto& match = *it;
            const std::size_t start =
                static_cast<std::size_t>(match.position(0));
            const std::size_t length =
                static_cast<std::size_t>(match.length(0));
            const std::size_t finish =
                std::min(start + length, chars.size());
            for (std::size_t i = start; i < finish; ++i) {
                if (chars[i] != '\n')
                    chars[i] = ' ';
            }
        }
    } catch (...) {
    }
    return chars;
}
static std::vector<std::size_t> build_line_offsets(
    const std::string& text) {
    std::vector<std::size_t> offsets;
    offsets.reserve(std::count(text.begin(), text.end(), '\n') + 1);
    offsets.push_back(0);
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n' && i + 1 <= text.size())
            offsets.push_back(i + 1);
    }
    return offsets;
}
static std::vector<std::string> split_lines_preserve_content(
    const std::string& text) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = text.find('\n', start);
        if (end == std::string::npos) {
            lines.emplace_back(text.substr(start));
            break;
        }
        lines.emplace_back(text.substr(start, end - start));
        start = end + 1;
    }
    if (lines.empty())
        lines.emplace_back();
    return lines;
}
static int offset_to_lineno(
    const std::vector<std::size_t>& offsets,
    std::size_t offset) {
    auto it = std::upper_bound(
        offsets.begin(),
        offsets.end(),
        offset);
    if (it == offsets.begin())
        return 1;
    --it;
    return static_cast<int>(
        std::distance(offsets.begin(), it) + 1);
}
static std::string trim_line(const std::string& line) {
    const auto first =
        line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const auto last =
        line.find_last_not_of(" \t\r\n");
    return line.substr(first, last - first + 1);
}
std::vector<Issue> find_matches_in_text(
    const std::string& text,
    const std::vector<std::regex>& compiled_patterns,
    const fs::path& path,
    const std::string& lang) {
    std::vector<Issue> matches;
    if (compiled_patterns.empty())
        return matches;
    const std::string cleaned =
        remove_comments_and_strings_preserve_offsets(
            text,
            lang);
    const std::vector<std::size_t> offsets =
        build_line_offsets(text);
    const std::vector<std::string> lines =
        split_lines_preserve_content(text);
    for (const auto& pattern : compiled_patterns) {
        try {
            std::sregex_iterator it(
                cleaned.begin(),
                cleaned.end(),
                pattern);
            const std::sregex_iterator end;
            for (; it != end; ++it) {
                try {
                    const auto& match = *it;
                    const std::size_t start =
                        static_cast<std::size_t>(
                            match.position(0));
                    const int line_no =
                        offset_to_lineno(offsets, start);
                    const int line_idx =
                        std::max(
                            0,
                            std::min(
                                static_cast<int>(lines.size()) - 1,
                                line_no - 1));
                    std::string snippet =
                        trim_line(
                            lines[
                                static_cast<std::size_t>(
                                    line_idx)]);
                    std::string match_text =
                        match.str(0);
                    if (match_text.size() > 300)
                        match_text.resize(300);
                    Issue issue;
                    issue.file = path.string();
                    issue.line = line_no;
                    issue.pattern =
                        pattern.mark_count()
                            ? "(complex)"
                            : "(pattern)";
                    issue.match_text =
                        std::move(match_text);
                    issue.snippet =
                        std::move(snippet);
                    matches.push_back(
                        std::move(issue));
                } catch (...) {
                    Issue issue;
                    issue.file = path.string();
                    issue.line = 0;
                    issue.pattern =
                        "(ERROR_MATCH)";
                    issue.match_text.clear();
                    issue.snippet =
                        "Error mapping match to line";
                    matches.push_back(
                        std::move(issue));
                }
            }
        } catch (...) {
        }
    }
    return matches;
}
std::vector<Issue> detect_injections_in_file(
    const fs::path& path,
    const std::unordered_map<
        std::string,
        std::vector<
            std::pair<std::string, std::regex>>>& compiled_by_lang,
    const std::vector<
        std::pair<std::string, std::regex>>& default_patterns,
    std::size_t min_size,
    std::size_t max_size,
    const std::vector<std::string>& ignore_exts) {
    std::vector<Issue> rv;
    try {
        std::string suffix =
            path.extension().string();
        std::transform(
            suffix.begin(),
            suffix.end(),
            suffix.begin(),
            [](unsigned char c) {
                return static_cast<char>(
                    std::tolower(c));
            });
        if (!suffix.empty() &&
            std::find(
                ignore_exts.begin(),
                ignore_exts.end(),
                suffix) != ignore_exts.end())
            return rv;
        std::error_code ec;
        const auto size =
            fs::file_size(path, ec);
        if (ec ||
            size < min_size ||
            (max_size > 0 && size > max_size))
            return rv;
    } catch (...) {
        return rv;
    }
    if (!is_text_file(path))
        return rv;
    std::string lang;
    std::string suffix =
        path.extension().string();
    std::transform(
        suffix.begin(),
        suffix.end(),
        suffix.begin(),
        [](unsigned char c) {
            return static_cast<char>(
                std::tolower(c));
        });
    auto lang_it =
        LANG_EXTENSIONS.find(suffix);
    if (lang_it != LANG_EXTENSIONS.end())
        lang = lang_it->second;
    std::vector<
        std::pair<std::string, std::regex>>
        compiled_patterns_pairs;
    if (!lang.empty()) {
        auto it =
            compiled_by_lang.find(lang);
        if (it != compiled_by_lang.end()) {
            compiled_patterns_pairs.insert(
                compiled_patterns_pairs.end(),
                it->second.begin(),
                it->second.end());
        }
    }
    compiled_patterns_pairs.insert(
        compiled_patterns_pairs.end(),
        default_patterns.begin(),
        default_patterns.end());
    if (compiled_patterns_pairs.empty())
        return rv;
    std::string text;
    try {
        std::ifstream fh(
            path,
            std::ios::binary);
        if (!fh) {
            Issue issue;
            issue.file = path.string();
            issue.line = 0;
            issue.pattern =
                "ERROR_READING";
            issue.match_text.clear();
            issue.snippet =
                "Error reading file";
            rv.push_back(
                std::move(issue));
            return rv;
        }
        fh.seekg(0, std::ios::end);
        const std::streamoff end =
            fh.tellg();
        if (end > 0) {
            text.resize(
                static_cast<std::size_t>(
                    end));
            fh.seekg(0, std::ios::beg);
            fh.read(
                text.data(),
                static_cast<std::streamsize>(
                    text.size()));
            if (!fh && !fh.eof()) {
                Issue issue;
                issue.file = path.string();
                issue.line = 0;
                issue.pattern =
                    "ERROR_READING";
                issue.match_text.clear();
                issue.snippet =
                    "Error reading file";
                rv.push_back(
                    std::move(issue));
                return rv;
            }
        } else if (end == 0) {
            text.clear();
        } else {
            Issue issue;
            issue.file = path.string();
            issue.line = 0;
            issue.pattern =
                "ERROR_READING";
            issue.match_text.clear();
            issue.snippet =
                "Error determining file size";
            rv.push_back(
                std::move(issue));
            return rv;
        }
    } catch (...) {
        Issue issue;
        issue.file = path.string();
        issue.line = 0;
        issue.pattern =
            "ERROR_READING";
        issue.match_text.clear();
        issue.snippet =
            "Error reading file";
        rv.push_back(
            std::move(issue));
        return rv;
    }
    const std::string cleaned =
        remove_comments_and_strings_preserve_offsets(
            text,
            lang);
    const std::vector<std::size_t> offsets =
        build_line_offsets(text);
    const std::vector<std::string> lines =
        split_lines_preserve_content(text);
    for (const auto& [pattern_string, pattern] :
         compiled_patterns_pairs) {
        try {
            std::sregex_iterator it(
                cleaned.begin(),
                cleaned.end(),
                pattern);
            const std::sregex_iterator end;
            for (; it != end; ++it) {
                try {
                    const auto& match = *it;
                    const std::size_t start =
                        static_cast<std::size_t>(
                            match.position(0));
                    const int line_no =
                        offset_to_lineno(
                            offsets,
                            start);
                    const int line_idx =
                        std::max(
                            0,
                            std::min(
                                static_cast<int>(
                                    lines.size()) - 1,
                                line_no - 1));
                    Issue issue;
                    issue.file =
                        path.string();
                    issue.line =
                        line_no;
                    issue.pattern =
                        pattern_string;
                    issue.match_text =
                        match.str(0);
                    if (issue.match_text.size() >
                        300)
                        issue.match_text.resize(300);
                    issue.snippet =
                        trim_line(
                            lines[
                                static_cast<std::size_t>(
                                    line_idx)]);
                    rv.push_back(
                        std::move(issue));
                } catch (...) {
                    Issue issue;
                    issue.file =
                        path.string();
                    issue.line = 0;
                    issue.pattern =
                        pattern_string;
                    issue.match_text.clear();
                    issue.snippet =
                        "Error mapping match to line";
                    rv.push_back(
                        std::move(issue));
                }
            }
        } catch (...) {
        }
    }
    return rv;
}
std::vector<Issue> scan_directory_for_injections(
    const fs::path& root_dir,
    const std::unordered_map<
        std::string,
        std::vector<
            std::pair<std::string, std::regex>>>& compiled_by_lang,
    const std::vector<
        std::pair<std::string, std::regex>>& default_patterns,
    int threads,
    std::size_t min_size,
    std::size_t max_size,
    const std::vector<std::string>& ignore_exts,
    const std::vector<std::string>& ignore_dirs) {
    if (threads < 1)
        threads = 1;
    std::vector<fs::path> files;
    try {
        fs::recursive_directory_iterator it(
            root_dir,
            fs::directory_options::
                skip_permission_denied);
        const fs::recursive_directory_iterator end;
        for (; it != end; ++it) {
            try {
                if (!it->is_regular_file())
                    continue;
                bool skip = false;
                for (const auto& part :
                     it->path()) {
                    std::string part_name =
                        part.string();
                    std::transform(
                        part_name.begin(),
                        part_name.end(),
                        part_name.begin(),
                        [](unsigned char c) {
                            return static_cast<char>(
                                std::tolower(c));
                        });
                    if (std::find(
                            ignore_dirs.begin(),
                            ignore_dirs.end(),
                            part_name) !=
                        ignore_dirs.end()) {
                        skip = true;
                        break;
                    }
                }
                if (!skip)
                    files.push_back(
                        it->path());
            } catch (...) {
                continue;
            }
        }
    } catch (...) {
        return {};
    }
    if (files.empty())
        return {};
    const std::size_t worker_count =
        std::min<std::size_t>(
            static_cast<std::size_t>(
                threads),
            files.size());
    std::atomic<std::size_t> next_index{0};
    std::vector<
        std::future<std::vector<Issue>>>
        futures;
    futures.reserve(worker_count);
    for (std::size_t worker = 0;
         worker < worker_count;
         ++worker) {
        futures.emplace_back(
            std::async(
                std::launch::async,
                [&files,
                 &next_index,
                 &compiled_by_lang,
                 &default_patterns,
                 min_size,
                 max_size,
                 &ignore_exts]() {
                    std::vector<Issue>
                        worker_issues;
                    while (true) {
                        const std::size_t index =
                            next_index.fetch_add(
                                1,
                                std::memory_order_relaxed);
                        if (index >=
                            files.size())
                            break;
                        std::vector<Issue>
                            found =
                            detect_injections_in_file(
                                files[index],
                                compiled_by_lang,
                                default_patterns,
                                min_size,
                                max_size,
                                ignore_exts);
                        worker_issues.insert(
                            worker_issues.end(),
                            std::make_move_iterator(
                                found.begin()),
                            std::make_move_iterator(
                                found.end()));
                    }
                    return worker_issues;
                }));
    }
    std::vector<Issue> issues;
    for (auto& future : futures) {
        try {
            auto result =
                future.get();
            issues.insert(
                issues.end(),
                std::make_move_iterator(
                    result.begin()),
                std::make_move_iterator(
                    result.end()));
        } catch (...) {
            continue;
        }
    }
    struct KeyHash {
        std::size_t operator()(
            const std::tuple<
                std::string,
                int,
                std::string,
                std::string>& t) const noexcept {
            const auto h1 =
                std::hash<std::string>{}(
                    std::get<0>(t));
            const auto h2 =
                std::hash<int>{}(
                    std::get<1>(t));
            const auto h3 =
                std::hash<std::string>{}(
                    std::get<2>(t));
            const auto h4 =
                std::hash<std::string>{}(
                    std::get<3>(t));
            std::size_t result = h1;
            result ^=
                h2 +
                static_cast<std::size_t>(
                    0x9e3779b9) +
                (result << 6) +
                (result >> 2);
            result ^=
                h3 +
                static_cast<std::size_t>(
                    0x9e3779b9) +
                (result << 6) +
                (result >> 2);
            result ^=
                h4 +
                static_cast<std::size_t>(
                    0x9e3779b9) +
                (result << 6) +
                (result >> 2);
            return result;
        }
    };
    std::unordered_set<
        std::tuple<
            std::string,
            int,
            std::string,
            std::string>,
        KeyHash> seen;
    seen.reserve(issues.size());
    std::vector<Issue> unique;
    unique.reserve(issues.size());
    for (auto& issue : issues) {
        std::string excerpt =
            issue.match_text;
        if (excerpt.size() > 80)
            excerpt.resize(80);
        auto key =
            std::make_tuple(
                issue.file,
                issue.line,
                issue.pattern,
                std::move(excerpt));
        if (seen.emplace(key).second)
            unique.push_back(
                std::move(issue));
    }
    return unique;
}
void save_results_csv(
    const std::vector<Issue>& issues,
    const fs::path& output_file) {
    std::ofstream fh(output_file);
    if (!fh) {
        std::cerr
            << "[!] Failed to open output file: "
            << output_file
            << std::endl;
        return;
    }
    fh << "File,Line,Pattern,Match,Snippet\n";
    const auto escape_csv =
        [](const std::string& s) {
            std::string result;
            result.reserve(
                s.size() + 2);
            result.push_back('"');
            for (char c : s) {
                if (c == '"')
                    result.push_back('"');
                result.push_back(c);
            }
            result.push_back('"');
            return result;
        };
    for (const auto& issue : issues) {
        fh << escape_csv(issue.file)
           << ","
           << issue.line
           << ","
           << escape_csv(issue.pattern)
           << ","
           << escape_csv(issue.match_text)
           << ","
           << escape_csv(issue.snippet)
           << "\n";
    }
    if (!fh) {
        std::cerr
            << "[!] Error while writing output file: "
            << output_file
            << std::endl;
        return;
    }
    std::cout
        << "Results saved to "
        << fs::absolute(output_file)
        << std::endl;
}
std::unordered_map<
    std::string,
    std::vector<
        std::pair<std::string, std::regex>>>
build_compiled_pattern_sets(
    const std::map<
        std::string,
        std::vector<std::string>>&
        custom_patterns) {
    std::unordered_map<
        std::string,
        std::vector<
            std::pair<std::string, std::regex>>>
        compiled_by_lang;
    compiled_by_lang.reserve(
        LANGUAGE_PATTERNS.size() +
        custom_patterns.size() +
        1);
    for (const auto& [language, patterns] :
         LANGUAGE_PATTERNS) {
        std::vector<
            std::pair<std::string, std::regex>>
            compiled;
        compiled.reserve(
            patterns.size());
        for (const auto& pattern :
             patterns) {
            std::regex regex_pattern;
            if (compile_regex(
                    pattern,
                    regex_pattern))
                compiled.emplace_back(
                    pattern,
                    std::move(
                        regex_pattern));
        }
        compiled_by_lang.emplace(
            language,
            std::move(compiled));
    }
    std::vector<
        std::pair<std::string, std::regex>>
        default_patterns;
    for (const auto& [language, patterns] :
         custom_patterns) {
        if (language == "all") {
            default_patterns.reserve(
                default_patterns.size() +
                patterns.size());
            for (const auto& pattern :
                 patterns) {
                std::regex regex_pattern;
                if (compile_regex(
                        pattern,
                        regex_pattern))
                    default_patterns.emplace_back(
                        pattern,
                        std::move(
                            regex_pattern));
            }
        } else {
            std::string normalized_language =
                language;
            std::transform(
                normalized_language.begin(),
                normalized_language.end(),
                normalized_language.begin(),
                [](unsigned char c) {
                    return static_cast<char>(
                        std::tolower(c));
                });
            auto& slot =
                compiled_by_lang[
                    normalized_language];
            slot.reserve(
                slot.size() +
                patterns.size());
            for (const auto& pattern :
                 patterns) {
                std::regex regex_pattern;
                if (compile_regex(
                        pattern,
                        regex_pattern))
                    slot.emplace_back(
                        pattern,
                        std::move(
                            regex_pattern));
            }
        }
    }
    compiled_by_lang["__default__"] =
        std::move(default_patterns);
    return compiled_by_lang;
}
std::map<
    std::string,
    std::vector<std::string>>
load_custom_patterns(
    const fs::path& config_file) {
    std::map<
        std::string,
        std::vector<std::string>>
        out;
    std::ifstream fh(config_file);
    if (!fh)
        return out;
    std::string first;
    std::getline(fh, first);
    if (!first.empty() &&
        first.find('{') !=
            std::string::npos) {
        fh.clear();
        fh.seekg(0);
        std::string all(
            (std::istreambuf_iterator<char>(
                fh)),
            std::istreambuf_iterator<char>());
        try {
            std::string s;
            s.reserve(all.size());
            bool in_quote = false;
            for (std::size_t i = 0;
                 i < all.size();
                 ++i) {
                const char c = all[i];
                if (c == '"' &&
                    (i == 0 ||
                     all[i - 1] != '\\'))
                    in_quote = !in_quote;
                if (!in_quote &&
                    std::isspace(
                        static_cast<unsigned char>(
                            c)))
                    continue;
                s.push_back(c);
            }
            std::regex kv_re(
                R"JSON("([^"]+)"\s*:\s*\[([^\]]*)\])JSON",
                std::regex_constants::ECMAScript);
            std::sregex_iterator it(
                s.begin(),
                s.end(),
                kv_re);
            const std::sregex_iterator end;
            for (; it != end; ++it) {
                const auto& match = *it;
                const std::string key =
                    match.str(1);
                const std::string array =
                    match.str(2);
                std::vector<std::string>
                    items;
                std::string current;
                bool in_quote_2 = false;
                for (std::size_t i = 0;
                     i < array.size();
                     ++i) {
                    const char c =
                        array[i];
                    if (c == '"' &&
                        (i == 0 ||
                         array[i - 1] != '\\')) {
                        in_quote_2 =
                            !in_quote_2;
                        if (!in_quote_2) {
                            items.push_back(
                                current);
                            current.clear();
                            std::size_t j =
                                i + 1;
                            while (
                                j < array.size() &&
                                (array[j] == ',' ||
                                 std::isspace(
                                     static_cast<unsigned char>(
                                         array[j]))))
                                ++j;
                            i =
                                j > 0
                                    ? j - 1
                                    : i;
                        }
                        continue;
                    }
                    if (in_quote_2)
                        current.push_back(c);
                }
                for (auto& item :
                     items)
                    out[key].push_back(
                        std::move(item));
            }
        } catch (...) {
            std::cerr
                << "[!] Error parsing custom patterns JSON (naive parser) - "
                   "ignoring custom patterns\n";
            return {};
        }
    } else {
        try {
            fh.clear();
            fh.seekg(0);
            std::string line;
            while (std::getline(
                fh,
                line)) {
                if (line.empty())
                    continue;
                const auto pos =
                    line.find(':');
                if (pos ==
                    std::string::npos)
                    continue;
                std::string key =
                    line.substr(0, pos);
                std::string pattern =
                    line.substr(pos + 1);
                const auto key_first =
                    key.find_first_not_of(
                        " \t\r\n");
                const auto key_last =
                    key.find_last_not_of(
                        " \t\r\n");
                const auto pattern_first =
                    pattern.find_first_not_of(
                        " \t\r\n");
                const auto pattern_last =
                    pattern.find_last_not_of(
                        " \t\r\n");
                if (key_first ==
                        std::string::npos ||
                    pattern_first ==
                        std::string::npos)
                    continue;
                key =
                    key.substr(
                        key_first,
                        key_last -
                            key_first +
                            1);
                pattern =
                    pattern.substr(
                        pattern_first,
                        pattern_last -
                            pattern_first +
                            1);
                if (!key.empty() &&
                    !pattern.empty())
                    out[key].push_back(
                        std::move(pattern));
            }
        } catch (...) {
        }
    }
    return out;
}
struct Args {
    std::string directory;
    std::string config;
    std::string output =
        "vulnerabilities_report";
    int threads = 8;
    std::vector<std::string>
        ignore_ext;
    std::vector<std::string>
        ignore_dir;
    std::size_t min_size = 0;
    std::size_t max_size = 5000000;
};
Args parse_args(
    int argc,
    char** argv) {
    Args args;
    if (argc < 2) {
        std::cerr
            << "Usage: "
            << argv[0]
            << " <directory> [--config file] "
               "[--output name] [--threads N] "
               "[--ignore-ext .png .bin] "
               "[--ignore-dir node_modules .git] "
               "[--min-size N] [--max-size N]\n";
        std::exit(1);
    }
    args.directory =
        argv[1];
    for (int i = 2;
         i < argc;
         ++i) {
        const std::string option =
            argv[i];
        try {
            if (option == "--config" &&
                i + 1 < argc) {
                args.config =
                    argv[++i];
            } else if (
                option == "--output" &&
                i + 1 < argc) {
                args.output =
                    argv[++i];
            } else if (
                option == "--threads" &&
                i + 1 < argc) {
                args.threads =
                    std::stoi(
                        argv[++i]);
                if (args.threads < 1)
                    args.threads = 1;
            } else if (
                option == "--ignore-ext") {
                ++i;
                while (
                    i < argc &&
                    argv[i][0] == '.') {
                    args.ignore_ext.emplace_back(
                        argv[i]);
                    ++i;
                }
                --i;
            } else if (
                option == "--ignore-dir") {
                ++i;
                while (
                    i < argc &&
                    argv[i][0] != '-') {
                    args.ignore_dir.emplace_back(
                        argv[i]);
                    ++i;
                }
                --i;
            } else if (
                option == "--min-size" &&
                i + 1 < argc) {
                args.min_size =
                    static_cast<std::size_t>(
                        std::stoull(
                            argv[++i]));
            } else if (
                option == "--max-size" &&
                i + 1 < argc) {
                args.max_size =
                    static_cast<std::size_t>(
                        std::stoull(
                            argv[++i]));
            } else {
                std::cerr
                    << "[!] Unknown arg: "
                    << option
                    << "\n";
            }
        } catch (
            const std::exception& e) {
            std::cerr
                << "[!] Invalid argument for "
                << option
                << ": "
                << e.what()
                << "\n";
        }
    }
    return args;
}
int main(
    int argc,
    char** argv) {
    try {
        Args args =
            parse_args(
                argc,
                argv);
        fs::path root(
            args.directory);
        std::error_code root_ec;
        if (!fs::exists(
                root,
                root_ec) ||
            root_ec ||
            !fs::is_directory(
                root,
                root_ec) ||
            root_ec) {
            std::cerr
                << "[!] Directory not found: "
                << root
                << std::endl;
            return 1;
        }
        std::map<
            std::string,
            std::vector<std::string>>
            custom;
        if (!args.config.empty())
            custom =
                load_custom_patterns(
                    args.config);
        auto compiled_all =
            build_compiled_pattern_sets(
                custom);
        std::vector<
            std::pair<
                std::string,
                std::regex>>
            default_patterns;
        auto it_def =
            compiled_all.find(
                "__default__");
        if (it_def !=
            compiled_all.end()) {
            default_patterns =
                std::move(
                    it_def->second);
            compiled_all.erase(
                it_def);
        }
        std::unordered_map<
            std::string,
            std::vector<
                std::pair<
                    std::string,
                    std::regex>>>
            compiled_by_lang;
        compiled_by_lang.reserve(
            compiled_all.size());
        for (auto& kv :
             compiled_all)
            compiled_by_lang.emplace(
                kv.first,
                std::move(
                    kv.second));
        std::vector<
            std::string>
            ignore_exts_norm;
        ignore_exts_norm.reserve(
            args.ignore_ext.size());
        for (const auto& ext :
             args.ignore_ext) {
            std::string normalized =
                ext;
            if (!normalized.empty() &&
                normalized[0] != '.')
                normalized.insert(
                    normalized.begin(),
                    '.');
            std::transform(
                normalized.begin(),
                normalized.end(),
                normalized.begin(),
                [](unsigned char c) {
                    return static_cast<char>(
                        std::tolower(c));
                });
            ignore_exts_norm.push_back(
                std::move(
                    normalized));
        }
        std::vector<
            std::string>
            ignore_dirs_norm;
        ignore_dirs_norm.reserve(
            args.ignore_dir.size() +
            DEFAULT_IGNORED_DIRS.size());
        for (const auto& directory :
             args.ignore_dir) {
            std::string normalized =
                directory;
            std::transform(
                normalized.begin(),
                normalized.end(),
                normalized.begin(),
                [](unsigned char c) {
                    return static_cast<char>(
                        std::tolower(c));
                });
            ignore_dirs_norm.push_back(
                std::move(
                    normalized));
        }
        for (const auto& directory :
             DEFAULT_IGNORED_DIRS)
            ignore_dirs_norm.push_back(
                directory);
        std::vector<Issue> issues =
            scan_directory_for_injections(
                root,
                compiled_by_lang,
                default_patterns,
                args.threads,
                args.min_size,
                args.max_size,
                ignore_exts_norm,
                ignore_dirs_norm);
        if (issues.empty()) {
            std::cout
                << " <| No potential vulnerabilities found.\n";
        } else {
            std::cout
                << "<| Potential vulnerabilities detected:\n\n";
            for (const auto& issue :
                 issues) {
                std::cout
                    << issue.file
                    << ":"
                    << issue.line
                    << "  -- "
                    << issue.pattern
                    << "  -- "
                    << issue.snippet
                    << "\n";
            }
            const fs::path output_path =
                args.output +
                ".csv";
            save_results_csv(
                issues,
                output_path);
        }
        return 0;
    } catch (
        const fs::filesystem_error& e) {
        std::cerr
            << "[!] Filesystem error: "
            << e.what()
            << "\n";
        return 1;
    } catch (
        const std::regex_error& e) {
        std::cerr
            << "[!] Regex error: "
            << e.what()
            << "\n";
        return 1;
    } catch (
        const std::bad_alloc& e) {
        std::cerr
            << "[!] Memory allocation error: "
            << e.what()
            << "\n";
        return 1;
    } catch (
        const std::exception& e) {
        std::cerr
            << "[!] Fatal error: "
            << e.what()
            << "\n";
        return 1;
    } catch (...) {
        std::cerr
            << "[!] Unknown fatal error.\n";
        return 1;
    }
}
//g++ -std=c++17 -O2 -pthread -Wall -Wextra -Wpedantic cves_cpp_0.2.cpp -o cves
