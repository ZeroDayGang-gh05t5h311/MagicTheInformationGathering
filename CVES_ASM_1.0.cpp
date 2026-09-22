#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>
#include <vector>
#include <regex>
#include <filesystem>
#include <set>
#include <fstream>
#include <future>
#include <mutex>
#include <thread>
#include <chrono>
#include <algorithm>
using namespace std;
namespace fs = std::filesystem;
struct PatternGroup {
    string name;
    vector<regex> patterns;
};
// Expanded Intel 64 / AMD64 x86/x86-64 vulnerability and security-relevant patterns.
// Pattern references are based on the Intel 64 and IA-32 Architectures Software
// Developer's Manuals and AMD64 Architecture Programmer's Manuals.
// The scanner identifies indicators; a match is NOT by itself proof of a vulnerability.
vector<PatternGroup> get_asm_vuln_patterns() {
    return {
        {"Buffer Overflow / Unsafe Memory Operations", {
            regex(R"(\bstrcpy\b)", regex_constants::icase),
            regex(R"(\bstrncpy\b)", regex_constants::icase),
            regex(R"(\bstrcat\b)", regex_constants::icase),
            regex(R"(\bstrncat\b)", regex_constants::icase),
            regex(R"(\bgets\b)", regex_constants::icase),
            regex(R"(\bfgets\b)", regex_constants::icase),
            regex(R"(\bscanf\b)", regex_constants::icase),
            regex(R"(\bfscanf\b)", regex_constants::icase),
            regex(R"(\bsscanf\b)", regex_constants::icase),
            regex(R"(\bvscanf\b)", regex_constants::icase),
            regex(R"(\bvsscanf\b)", regex_constants::icase),
            regex(R"(\bmemcpy\b)", regex_constants::icase),
            regex(R"(\bmemmove\b)", regex_constants::icase),
            regex(R"(\bmemset\b)", regex_constants::icase),
            regex(R"(\bmemchr\b)", regex_constants::icase),
            regex(R"(\bmovs\b)", regex_constants::icase),
            regex(R"(\bmovsb\b)", regex_constants::icase),
            regex(R"(\bmovsw\b)", regex_constants::icase),
            regex(R"(\bmovsd\b)", regex_constants::icase),
            regex(R"(\bmovsq\b)", regex_constants::icase),
            regex(R"(\bstos\b)", regex_constants::icase),
            regex(R"(\bstosb\b)", regex_constants::icase),
            regex(R"(\bstosw\b)", regex_constants::icase),
            regex(R"(\bstosd\b)", regex_constants::icase),
            regex(R"(\bstosq\b)", regex_constants::icase),
            regex(R"(\blods\b)", regex_constants::icase),
            regex(R"(\blodsb\b)", regex_constants::icase),
            regex(R"(\blodsw\b)", regex_constants::icase),
            regex(R"(\blodsd\b)", regex_constants::icase),
            regex(R"(\blodsq\b)", regex_constants::icase),
            regex(R"(\bcmps\b)", regex_constants::icase),
            regex(R"(\bcmpsb\b)", regex_constants::icase),
            regex(R"(\bcmpsw\b)", regex_constants::icase),
            regex(R"(\bcmpsd\b)", regex_constants::icase),
            regex(R"(\bcmpsq\b)", regex_constants::icase),
            regex(R"(\bscas\b)", regex_constants::icase),
            regex(R"(\bscasb\b)", regex_constants::icase),
            regex(R"(\bscasw\b)", regex_constants::icase),
            regex(R"(\bscasd\b)", regex_constants::icase),
            regex(R"(\bscasq\b)", regex_constants::icase),
            regex(R"(\bxor\s+[a-z0-9]+\s*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\badd\s+[a-z0-9]+\s*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\bsub\s+[a-z0-9]+\s*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\binc\s+[a-z0-9]+\b)", regex_constants::icase),
            regex(R"(\bdec\s+[a-z0-9]+\b)", regex_constants::icase),
            regex(R"(\bpush\s+.*)", regex_constants::icase),
            regex(R"(\bpop\s+.*)", regex_constants::icase)
        }},
        {"Unsafe Function Call / Library Routines", {
            regex(R"(\bcall\s+strcpy\b)", regex_constants::icase),
            regex(R"(\bcall\s+strncpy\b)", regex_constants::icase),
            regex(R"(\bcall\s+strcat\b)", regex_constants::icase),
            regex(R"(\bcall\s+strncat\b)", regex_constants::icase),
            regex(R"(\bcall\s+gets\b)", regex_constants::icase),
            regex(R"(\bcall\s+scanf\b)", regex_constants::icase),
            regex(R"(\bcall\s+fscanf\b)", regex_constants::icase),
            regex(R"(\bcall\s+sscanf\b)", regex_constants::icase),
            regex(R"(\bcall\s+sprintf\b)", regex_constants::icase),
            regex(R"(\bcall\s+vsprintf\b)", regex_constants::icase),
            regex(R"(\bcall\s+system\b)", regex_constants::icase),
            regex(R"(\bcall\s+popen\b)", regex_constants::icase),
            regex(R"(\bcall\s+execve\b)", regex_constants::icase),
            regex(R"(\bcall\s+execv\b)", regex_constants::icase),
            regex(R"(\bcall\s+execvp\b)", regex_constants::icase),
            regex(R"(\bcall\s+execl\b)", regex_constants::icase),
            regex(R"(\bcall\s+execlp\b)", regex_constants::icase),
            regex(R"(\bcall\s+memcpy\b)", regex_constants::icase),
            regex(R"(\bcall\s+memmove\b)", regex_constants::icase),
            regex(R"(\bcall\s+memset\b)", regex_constants::icase),
            regex(R"(\bcall\s+free\b)", regex_constants::icase),
            regex(R"(\bcall\s+malloc\b)", regex_constants::icase),
            regex(R"(\bcall\s+calloc\b)", regex_constants::icase),
            regex(R"(\bcall\s+realloc\b)", regex_constants::icase)
        }},
        {"Hardcoded Secrets / Data Strings", {
            regex(R"(\bdb\s+\".*password.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*passwd.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*pass.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*secret.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*private.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*key.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*token.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*credential.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*api[_-]?key.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*auth.*\")", regex_constants::icase),
            regex(R"(\bdb\s+\".*bearer.*\")", regex_constants::icase),
            regex(R"(\bdata\s+\".*password.*\")", regex_constants::icase),
            regex(R"(\bdata\s+\".*secret.*\")", regex_constants::icase),
            regex(R"(\bdata\s+\".*private.*\")", regex_constants::icase),
            regex(R"(\bdata\s+\".*token.*\")", regex_constants::icase),
            regex(R"(\bdata\s+\".*credential.*\")", regex_constants::icase),
            regex(R"(\basciz\s+\".*password.*\")", regex_constants::icase),
            regex(R"(\basciz\s+\".*secret.*\")", regex_constants::icase),
            regex(R"(\basciz\s+\".*token.*\")", regex_constants::icase),
            regex(R"(\basciz\s+\".*key.*\")", regex_constants::icase)
        }},
        {"Privilege / Permissions / Escalation Instructions", {
            regex(R"(\biopl\b)", regex_constants::icase),
            regex(R"(\bcli\b)", regex_constants::icase),
            regex(R"(\bsti\b)", regex_constants::icase),
            regex(R"(\bhlt\b)", regex_constants::icase),
            regex(R"(\bin\s+)", regex_constants::icase),
            regex(R"(\bout\s+)", regex_constants::icase),
            regex(R"(\bins\b)", regex_constants::icase),
            regex(R"(\bouts\b)", regex_constants::icase),
            regex(R"(\binsb\b)", regex_constants::icase),
            regex(R"(\binsw\b)", regex_constants::icase),
            regex(R"(\binsd\b)", regex_constants::icase),
            regex(R"(\boutsb\b)", regex_constants::icase),
            regex(R"(\boutsw\b)", regex_constants::icase),
            regex(R"(\boutsd\b)", regex_constants::icase),
            regex(R"(\blgdt\b)", regex_constants::icase),
            regex(R"(\blidt\b)", regex_constants::icase),
            regex(R"(\blldt\b)", regex_constants::icase),
            regex(R"(\bltr\b)", regex_constants::icase),
            regex(R"(\bsgdt\b)", regex_constants::icase),
            regex(R"(\bstr\b)", regex_constants::icase),
            regex(R"(\bverr\b)", regex_constants::icase),
            regex(R"(\bverw\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bsetuid\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bsetgid\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bchmod\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\bchown\b)", regex_constants::icase),
            regex(R"(\bint\s+0x80\b.*\brwx\b)", regex_constants::icase)
        }},
        {"Suspicious Syscalls / Interrupts", {
            regex(R"(\bint\s+0x80\b)", regex_constants::icase),
            regex(R"(\bint\s+0x2e\b)", regex_constants::icase),
            regex(R"(\bint\s+0x81\b)", regex_constants::icase),
            regex(R"(\bint\s+0x82\b)", regex_constants::icase),
            regex(R"(\bint\s+0x90\b)", regex_constants::icase),
            regex(R"(\bsyscall\b)", regex_constants::icase),
            regex(R"(\bsysret\b)", regex_constants::icase),
            regex(R"(\bsysenter\b)", regex_constants::icase),
            regex(R"(\bsysexit\b)", regex_constants::icase),
            regex(R"(\bsysexitq\b)", regex_constants::icase),
            regex(R"(\biret\b)", regex_constants::icase),
            regex(R"(\biretd\b)", regex_constants::icase),
            regex(R"(\biretq\b)", regex_constants::icase),
            regex(R"(\btrap\b)", regex_constants::icase),
            regex(R"(\bint[123]\b)", regex_constants::icase),
            regex(R"(\binto\b)", regex_constants::icase),
            regex(R"(\beret\b)", regex_constants::icase)
        }},
        {"Control Flow / ROP / JOP / Jump Gadgets", {
            regex(R"(\bjmp\s+[a-zA-Z0-9_]+\b)", regex_constants::icase),
            regex(R"(\bjmp\s*\[.*\])", regex_constants::icase),
            regex(R"(\bjmp\s+[a-zA-Z0-9_]+\+.*)", regex_constants::icase),
            regex(R"(\bcall\s*\[.*\])", regex_constants::icase),
            regex(R"(\bcall\s+[a-zA-Z0-9_]+\+.*)", regex_constants::icase),
            regex(R"(\bpush\s+[^\n]*;\s*ret\b)", regex_constants::icase),
            regex(R"(\bpop\s+[^\n]*;\s*ret\b)", regex_constants::icase),
            regex(R"(\bxchg\s+.*,\s*esp\b)", regex_constants::icase),
            regex(R"(\bxchg\s+.*,\s*rsp\b)", regex_constants::icase),
            regex(R"(\bret\b)", regex_constants::icase),
            regex(R"(\bretn\b)", regex_constants::icase),
            regex(R"(\bretf\b)", regex_constants::icase),
            regex(R"(\bleave\b)", regex_constants::icase),
            regex(R"(\bloop\b)", regex_constants::icase),
            regex(R"(\bloope\b)", regex_constants::icase),
            regex(R"(\bloopne\b)", regex_constants::icase),
            regex(R"(\bjecxz\b)", regex_constants::icase),
            regex(R"(\bjrcxz\b)", regex_constants::icase)
        }},
        {"Conditional Branch / Control-Flow Instructions", {
            regex(R"(\bja\b|\bjae\b|\bjb\b|\bjbe\b)", regex_constants::icase),
            regex(R"(\bjc\b|\bje\b|\bjg\b|\bjge\b)", regex_constants::icase),
            regex(R"(\bjl\b|\bjle\b|\bjna\b|\bjnae\b)", regex_constants::icase),
            regex(R"(\bjnb\b|\bjnbe\b|\bjnc\b|\bjne\b)", regex_constants::icase),
            regex(R"(\bjng\b|\bjnge\b|\bjnl\b|\bjnle\b)", regex_constants::icase),
            regex(R"(\bjno\b|\bjnp\b|\bjns\b|\bjnz\b)", regex_constants::icase),
            regex(R"(\bjo\b|\bjp\b|\bjs\b|\bjz\b)", regex_constants::icase),
            regex(R"(\bjecxz\b|\bjrcxz\b)", regex_constants::icase),
            regex(R"(\bloop\b|\bloope\b|\bloopne\b)", regex_constants::icase)
        }},
        {"Arithmetic / Integer Overflow / Underflow Risks", {
            regex(R"(\badd\b)", regex_constants::icase),
            regex(R"(\bsub\b)", regex_constants::icase),
            regex(R"(\badc\b)", regex_constants::icase),
            regex(R"(\bsbb\b)", regex_constants::icase),
            regex(R"(\binc\b)", regex_constants::icase),
            regex(R"(\bdec\b)", regex_constants::icase),
            regex(R"(\bneg\b)", regex_constants::icase),
            regex(R"(\bmul\b)", regex_constants::icase),
            regex(R"(\bimul\b)", regex_constants::icase),
            regex(R"(\bdiv\b)", regex_constants::icase),
            regex(R"(\bidiv\b)", regex_constants::icase),
            regex(R"(\bdivl\b)", regex_constants::icase),
            regex(R"(\bidivl\b)", regex_constants::icase),
            regex(R"(\bdivq\b)", regex_constants::icase),
            regex(R"(\bidivq\b)", regex_constants::icase),
            regex(R"(\bcqo\b)", regex_constants::icase),
            regex(R"(\bcdq\b)", regex_constants::icase),
            regex(R"(\bcwd\b)", regex_constants::icase),
            regex(R"(\bcwde\b)", regex_constants::icase),
            regex(R"(\bjo\b|\bjno\b)", regex_constants::icase),
            regex(R"(\bjc\b|\bjnc\b)", regex_constants::icase),
            regex(R"(\bjb\b|\bjae\b|\bjbe\b|\bja\b)", regex_constants::icase),
            regex(R"(\bjl\b|\bjge\b|\bjle\b|\bjg\b)", regex_constants::icase)
        }},
        {"Bit Manipulation / Masking Operations", {
            regex(R"(\band\b)", regex_constants::icase),
            regex(R"(\bor\b)", regex_constants::icase),
            regex(R"(\bxor\b)", regex_constants::icase),
            regex(R"(\bnot\b)", regex_constants::icase),
            regex(R"(\btest\b)", regex_constants::icase),
            regex(R"(\bbt\b)", regex_constants::icase),
            regex(R"(\bbts\b)", regex_constants::icase),
            regex(R"(\bbtr\b)", regex_constants::icase),
            regex(R"(\bbtc\b)", regex_constants::icase),
            regex(R"(\bbsf\b)", regex_constants::icase),
            regex(R"(\bbsr\b)", regex_constants::icase),
            regex(R"(\btzcnt\b)", regex_constants::icase),
            regex(R"(\blzcnt\b)", regex_constants::icase),
            regex(R"(\bpopcnt\b)", regex_constants::icase),
            regex(R"(\bpext\b)", regex_constants::icase),
            regex(R"(\bpdep\b)", regex_constants::icase)
        }},
        {"Shift / Rotate / Bitwise Arithmetic", {
            regex(R"(\bshl\b|\bsal\b)", regex_constants::icase),
            regex(R"(\bshr\b)", regex_constants::icase),
            regex(R"(\bsar\b)", regex_constants::icase),
            regex(R"(\brol\b)", regex_constants::icase),
            regex(R"(\bror\b)", regex_constants::icase),
            regex(R"(\brcl\b)", regex_constants::icase),
            regex(R"(\brcr\b)", regex_constants::icase),
            regex(R"(\brdcl\b)", regex_constants::icase),
            regex(R"(\brdcr\b)", regex_constants::icase),
            regex(R"(\bshld\b)", regex_constants::icase),
            regex(R"(\bshrd\b)", regex_constants::icase),
            regex(R"(\bshlx\b)", regex_constants::icase),
            regex(R"(\bshrx\b)", regex_constants::icase),
            regex(R"(\bsarx\b)", regex_constants::icase)
        }},
        {"Atomic / Synchronization / Race-Relevant Instructions", {
            regex(R"(\block\b)", regex_constants::icase),
            regex(R"(\bxchg\s+.*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\bxadd\b)", regex_constants::icase),
            regex(R"(\bcmpxchg\b)", regex_constants::icase),
            regex(R"(\bcmpxchg8b\b)", regex_constants::icase),
            regex(R"(\bcmpxchg16b\b)", regex_constants::icase),
            regex(R"(\bxchg\b)", regex_constants::icase),
            regex(R"(\bmonitor\b)", regex_constants::icase),
            regex(R"(\bmwait\b)", regex_constants::icase),
            regex(R"(\bumonitor\b)", regex_constants::icase),
            regex(R"(\bumwait\b)", regex_constants::icase)
        }},
        {"Memory Ordering / Cache / Fence Operations", {
            regex(R"(\bclflush\b)", regex_constants::icase),
            regex(R"(\bclflushopt\b)", regex_constants::icase),
            regex(R"(\bclwb\b)", regex_constants::icase),
            regex(R"(\bcldemote\b)", regex_constants::icase),
            regex(R"(\blfence\b)", regex_constants::icase),
            regex(R"(\bsfence\b)", regex_constants::icase),
            regex(R"(\bmfence\b)", regex_constants::icase),
            regex(R"(\bserialize\b)", regex_constants::icase),
            regex(R"(\bprefetch\b)", regex_constants::icase),
            regex(R"(\bprefetchnta\b)", regex_constants::icase),
            regex(R"(\bprefetcht0\b)", regex_constants::icase),
            regex(R"(\bprefetcht1\b)", regex_constants::icase),
            regex(R"(\bprefetcht2\b)", regex_constants::icase),
            regex(R"(\bclzero\b)", regex_constants::icase)
        }},
        {"System / Privileged Register Operations", {
            regex(R"(\bmov\s+(cr[0-9]+|dr[0-9]+)\b)", regex_constants::icase),
            regex(R"(\bmov\s+[a-z0-9]+\s*,\s*cr[0-9]+\b)", regex_constants::icase),
            regex(R"(\bmov\s+[a-z0-9]+\s*,\s*dr[0-9]+\b)", regex_constants::icase),
            regex(R"(\bmov\s+cr[0-9]+\s*,)", regex_constants::icase),
            regex(R"(\bmov\s+dr[0-9]+\s*,)", regex_constants::icase),
            regex(R"(\bclts\b)", regex_constants::icase),
            regex(R"(\blmsw\b)", regex_constants::icase),
            regex(R"(\binvlpg\b)", regex_constants::icase),
            regex(R"(\binvpcid\b)", regex_constants::icase),
            regex(R"(\binvept\b)", regex_constants::icase),
            regex(R"(\binvvpid\b)", regex_constants::icase),
            regex(R"(\binvept\b)", regex_constants::icase),
            regex(R"(\bwritecr[0-9]+\b)", regex_constants::icase),
            regex(R"(\breadcr[0-9]+\b)", regex_constants::icase)
        }},
        {"Descriptor / Segmentation / Protection Operations", {
            regex(R"(\blgdt\b)", regex_constants::icase),
            regex(R"(\blidt\b)", regex_constants::icase),
            regex(R"(\bsgdt\b)", regex_constants::icase),
            regex(R"(\bsidt\b)", regex_constants::icase),
            regex(R"(\blldt\b)", regex_constants::icase),
            regex(R"(\bstr\b)", regex_constants::icase),
            regex(R"(\bltr\b)", regex_constants::icase),
            regex(R"(\bverr\b)", regex_constants::icase),
            regex(R"(\bverw\b)", regex_constants::icase),
            regex(R"(\barpl\b)", regex_constants::icase),
            regex(R"(\bclts\b)", regex_constants::icase),
            regex(R"(\bsmsw\b)", regex_constants::icase)
        }},
        {"MSR / CPU Configuration Operations", {
            regex(R"(\brdmsr\b)", regex_constants::icase),
            regex(R"(\bwrmsr\b)", regex_constants::icase),
            regex(R"(\brdmsrlist\b)", regex_constants::icase),
            regex(R"(\bwrmsrlist\b)", regex_constants::icase),
            regex(R"(\brdpid\b)", regex_constants::icase),
            regex(R"(\brdtsc\b)", regex_constants::icase),
            regex(R"(\brdtscp\b)", regex_constants::icase),
            regex(R"(\bwrfsbase\b)", regex_constants::icase),
            regex(R"(\bwrgsbase\b)", regex_constants::icase),
            regex(R"(\brdfsbase\b)", regex_constants::icase),
            regex(R"(\brdgsbase\b)", regex_constants::icase)
        }},
        {"Virtualization / Hypervisor Instructions", {
            regex(R"(\bvmcall\b)", regex_constants::icase),
            regex(R"(\bvmlaunch\b)", regex_constants::icase),
            regex(R"(\bvmresume\b)", regex_constants::icase),
            regex(R"(\bvmxoff\b)", regex_constants::icase),
            regex(R"(\bvmxon\b)", regex_constants::icase),
            regex(R"(\bvmclear\b)", regex_constants::icase),
            regex(R"(\bvmptrld\b)", regex_constants::icase),
            regex(R"(\bvmptrst\b)", regex_constants::icase),
            regex(R"(\bvmlist\b)", regex_constants::icase),
            regex(R"(\bvmread\b)", regex_constants::icase),
            regex(R"(\bvmwrite\b)", regex_constants::icase),
            regex(R"(\binvept\b)", regex_constants::icase),
            regex(R"(\binvvpid\b)", regex_constants::icase),
            regex(R"(\bvmrun\b)", regex_constants::icase),
            regex(R"(\bvmmcall\b)", regex_constants::icase),
            regex(R"(\bvmload\b)", regex_constants::icase),
            regex(R"(\bvmsave\b)", regex_constants::icase),
            regex(R"(\bclgi\b)", regex_constants::icase),
            regex(R"(\bstgi\b)", regex_constants::icase),
            regex(R"(\binvlpga\b)", regex_constants::icase),
            regex(R"(\bskinit\b)", regex_constants::icase),
            regex(R"(\bvmgexit\b)", regex_constants::icase)
        }},
        {"Interrupt / Exception / Return Instructions", {
            regex(R"(\bint\s+[0-9a-fx]+\b)", regex_constants::icase),
            regex(R"(\bint1\b)", regex_constants::icase),
            regex(R"(\bint3\b)", regex_constants::icase),
            regex(R"(\binto\b)", regex_constants::icase),
            regex(R"(\biret\b)", regex_constants::icase),
            regex(R"(\biretd\b)", regex_constants::icase),
            regex(R"(\biretq\b)", regex_constants::icase),
            regex(R"(\bsysexit\b)", regex_constants::icase),
            regex(R"(\bsysexitq\b)", regex_constants::icase),
            regex(R"(\bsysret\b)", regex_constants::icase),
            regex(R"(\bsysretq\b)", regex_constants::icase),
            regex(R"(\bsysenter\b)", regex_constants::icase)
        }},
        {"Format String / Debug / Information Leakage", {
            regex(R"(\bprintf\b)", regex_constants::icase),
            regex(R"(\bfprintf\b)", regex_constants::icase),
            regex(R"(\bsprintf\b)", regex_constants::icase),
            regex(R"(\bsnprintf\b)", regex_constants::icase),
            regex(R"(\bvsprintf\b)", regex_constants::icase),
            regex(R"(\bvsnprintf\b)", regex_constants::icase),
            regex(R"(\bvprintf\b)", regex_constants::icase),
            regex(R"(\bvdprintf\b)", regex_constants::icase),
            regex(R"(\bwprintf\b)", regex_constants::icase),
            regex(R"(\bwprintf_s\b)", regex_constants::icase),
            regex(R"(\bdebug\b)", regex_constants::icase),
            regex(R"(\bprintk\b)", regex_constants::icase),
            regex(R"(\bputs\b)", regex_constants::icase),
            regex(R"(\bputchar\b)", regex_constants::icase),
            regex(R"(\bperror\b)", regex_constants::icase)
        }},
        {"Memory Allocation / Lifetime Indicators", {
            regex(R"(\bmalloc\b)", regex_constants::icase),
            regex(R"(\bcalloc\b)", regex_constants::icase),
            regex(R"(\brealloc\b)", regex_constants::icase),
            regex(R"(\bfree\b)", regex_constants::icase),
            regex(R"(\bnew\b)", regex_constants::icase),
            regex(R"(\bdelete\b)", regex_constants::icase),
            regex(R"(\bdelete\[\])", regex_constants::icase),
            regex(R"(\bcall\s+malloc\b)", regex_constants::icase),
            regex(R"(\bcall\s+calloc\b)", regex_constants::icase),
            regex(R"(\bcall\s+realloc\b)", regex_constants::icase),
            regex(R"(\bcall\s+free\b)", regex_constants::icase)
        }},
        {"x87 Floating-Point Instructions", {
            regex(R"(\bfld\b)", regex_constants::icase),
            regex(R"(\bfst\b)", regex_constants::icase),
            regex(R"(\bfstp\b)", regex_constants::icase),
            regex(R"(\bfild\b)", regex_constants::icase),
            regex(R"(\bfist\b)", regex_constants::icase),
            regex(R"(\bfistp\b)", regex_constants::icase),
            regex(R"(\bfadd\b)", regex_constants::icase),
            regex(R"(\bfaddp\b)", regex_constants::icase),
            regex(R"(\bfsub\b)", regex_constants::icase),
            regex(R"(\bfsubp\b)", regex_constants::icase),
            regex(R"(\bfmul\b)", regex_constants::icase),
            regex(R"(\bfmulp\b)", regex_constants::icase),
            regex(R"(\bfdiv\b)", regex_constants::icase),
            regex(R"(\bfdivp\b)", regex_constants::icase),
            regex(R"(\bfcom\b)", regex_constants::icase),
            regex(R"(\bfcomp\b)", regex_constants::icase),
            regex(R"(\bfxch\b)", regex_constants::icase),
            regex(R"(\bfnstenv\b)", regex_constants::icase),
            regex(R"(\bfstenv\b)", regex_constants::icase),
            regex(R"(\bfxsave\b)", regex_constants::icase),
            regex(R"(\bfxrstor\b)", regex_constants::icase),
            regex(R"(\bxsave\b)", regex_constants::icase),
            regex(R"(\bxrstor\b)", regex_constants::icase)
        }},
        {"MMX / SIMD State Instructions", {
            regex(R"(\bemms\b)", regex_constants::icase),
            regex(R"(\bfemms\b)", regex_constants::icase),
            regex(R"(\bmovd\b)", regex_constants::icase),
            regex(R"(\bmovq\b)", regex_constants::icase),
            regex(R"(\bpacksswb\b)", regex_constants::icase),
            regex(R"(\bpackuswb\b)", regex_constants::icase),
            regex(R"(\bpaddb\b)", regex_constants::icase),
            regex(R"(\bpaddw\b)", regex_constants::icase),
            regex(R"(\bpaddd\b)", regex_constants::icase),
            regex(R"(\bpsubb\b)", regex_constants::icase),
            regex(R"(\bpmullw\b)", regex_constants::icase),
            regex(R"(\bpmulhw\b)", regex_constants::icase)
        }},
        {"SSE / SSE2 / SSE3 / SSSE3 / SSE4 Instructions", {
            regex(R"(\bmovaps\b|\bmovups\b|\bmovapd\b|\bmovupd\b)", regex_constants::icase),
            regex(R"(\bmovdqa\b|\bmovdqu\b)", regex_constants::icase),
            regex(R"(\baddps\b|\baddpd\b|\baddss\b|\baddsd\b)", regex_constants::icase),
            regex(R"(\bsubps\b|\bsubpd\b|\bsubss\b|\bsubsd\b)", regex_constants::icase),
            regex(R"(\bmulps\b|\bmulpd\b|\bmulss\b|\bmulsd\b)", regex_constants::icase),
            regex(R"(\bdivps\b|\bdivpd\b|\bdivss\b|\bdivsd\b)", regex_constants::icase),
            regex(R"(\bminps\b|\bminpd\b|\bmaxps\b|\bmaxpd\b)", regex_constants::icase),
            regex(R"(\bandps\b|\bandpd\b|\bandnps\b|\bandnpd\b)", regex_constants::icase),
            regex(R"(\borps\b|\borpd\b|\bxorps\b|\bxorpd\b)", regex_constants::icase),
            regex(R"(\bcmpps\b|\bcmppd\b|\bcmpss\b|\bcmpsd\b)", regex_constants::icase),
            regex(R"(\bcomiss\b|\bucomiss\b|\bcomisd\b|\bucomisd\b)", regex_constants::icase),
            regex(R"(\bsqrtps\b|\bsqrtpd\b|\bsqrtss\b|\bsqrtsd\b)", regex_constants::icase),
            regex(R"(\bshufps\b|\bshufpd\b)", regex_constants::icase),
            regex(R"(\bpshufb\b)", regex_constants::icase),
            regex(R"(\bphaddw\b|\bphaddd\b|\bphsubw\b|\bphsubd\b)", regex_constants::icase),
            regex(R"(\bpmaddubsw\b)", regex_constants::icase),
            regex(R"(\bpmulhrsw\b)", regex_constants::icase),
            regex(R"(\bpabsb\b|\bpabsw\b|\bpabsd\b)", regex_constants::icase),
            regex(R"(\bptest\b)", regex_constants::icase),
            regex(R"(\bpmovmskb\b)", regex_constants::icase),
            regex(R"(\bmaskmovdqu\b)", regex_constants::icase)
        }},
        {"AVX / AVX2 Vector Instructions", {
            regex(R"(\bvmovaps\b|\bvmovups\b|\bvmovapd\b|\bvmovupd\b)", regex_constants::icase),
            regex(R"(\bvaddps\b|\bvaddpd\b|\bvaddss\b|\bvaddsd\b)", regex_constants::icase),
            regex(R"(\bvsubps\b|\bvsubpd\b|\bvsubss\b|\bvsubsd\b)", regex_constants::icase),
            regex(R"(\bvmulps\b|\bvmulpd\b|\bvmulss\b|\bvmulsd\b)", regex_constants::icase),
            regex(R"(\bvdivps\b|\bvdivpd\b|\bvdivss\b|\bvdivsd\b)", regex_constants::icase),
            regex(R"(\bvminps\b|\bvminpd\b|\bvmaxps\b|\bvmaxpd\b)", regex_constants::icase),
            regex(R"(\bvandps\b|\bvandpd\b|\bvandnps\b|\bvandnpd\b)", regex_constants::icase),
            regex(R"(\bvorps\b|\bvorpd\b|\bvxorps\b|\bvxorpd\b)", regex_constants::icase),
            regex(R"(\bvcmpps\b|\bvcmppd\b|\bvcmpss\b|\bvcmpsd\b)", regex_constants::icase),
            regex(R"(\bvsqrtps\b|\bvsqrtpd\b|\bvsqrtss\b|\bvsqrtsd\b)", regex_constants::icase),
            regex(R"(\bvshufps\b|\bvshufpd\b)", regex_constants::icase),
            regex(R"(\bvperm2f128\b)", regex_constants::icase),
            regex(R"(\bvpermq\b|\bvpermpd\b)", regex_constants::icase),
            regex(R"(\bvpshufb\b)", regex_constants::icase),
            regex(R"(\bvpmovmskb\b)", regex_constants::icase),
            regex(R"(\bvptest\b)", regex_constants::icase),
            regex(R"(\bvzeroupper\b)", regex_constants::icase),
            regex(R"(\bvzeroall\b)", regex_constants::icase),
            regex(R"(\bvbroadcastss\b|\bvbroadcastsd\b|\bvpbroadcastb\b|\bvpbroadcastw\b)", regex_constants::icase),
            regex(R"(\bvpgatherdd\b|\bvpgatherdq\b|\bvpgatherqd\b|\bvpgatherqq\b)", regex_constants::icase),
            regex(R"(\bvscatterdps\b|\bvscatterdpd\b|\bvscatterqps\b|\bvscatterqpd\b)", regex_constants::icase)
        }},
        {"AVX-512 / Masking / Vector State Instructions", {
            regex(R"(\bvmovdqa32\b|\bvmovdqa64\b)", regex_constants::icase),
            regex(R"(\bvmovdqu8\b|\bvmovdqu16\b|\bvmovdqu32\b|\bvmovdqu64\b)", regex_constants::icase),
            regex(R"(\bvaddps\b|\bvaddpd\b|\bvsubps\b|\bvsubpd\b)", regex_constants::icase),
            regex(R"(\bvpaddb\b|\bvpaddw\b|\bvpaddd\b|\bvpaddq\b)", regex_constants::icase),
            regex(R"(\bvpsubb\b|\bvpsubw\b|\bvpsubd\b|\bvpsubq\b)", regex_constants::icase),
            regex(R"(\bvpmullq\b|\bvpmulld\b|\bvpmullw\b)", regex_constants::icase),
            regex(R"(\bvpcmpd\b|\bvpcmpq\b|\bvpcmpb\b|\bvpcmpw\b)", regex_constants::icase),
            regex(R"(\bvptestmb\b|\bvptestmd\b|\bvptestmq\b|\bvptestmw\b)", regex_constants::icase),
            regex(R"(\bkandb\b|\bkandw\b|\bkandd\b|\bkandq\b)", regex_constants::icase),
            regex(R"(\bkorb\b|\bkorw\b|\bkord\b|\bkorq\b)", regex_constants::icase),
            regex(R"(\bkxor\b|\bkxorb\b|\bkxorw\b|\bkxord\b|\bkxorq\b)", regex_constants::icase),
            regex(R"(\bknot\b)", regex_constants::icase),
            regex(R"(\bkmovb\b|\bkmovw\b|\bkmovd\b|\bkmovq\b)", regex_constants::icase),
            regex(R"(\bkshiftlb\b|\bkshiftlw\b|\bkshiftld\b|\bkshiftlq\b)", regex_constants::icase),
            regex(R"(\bkshiftrb\b|\bkshiftrw\b|\bkshiftrd\b|\bkshiftrq\b)", regex_constants::icase),
            regex(R"(\bvcompress\b|\bvexpand\b)", regex_constants::icase),
            regex(R"(\bvpermb\b|\bvpermw\b|\bvpermd\b|\bvpermq\b)", regex_constants::icase),
            regex(R"(\bvscatter\b|\bvgather\b)", regex_constants::icase)
        }},
        {"Cryptographic / Hash Instructions", {
            regex(R"(\baesenc\b)", regex_constants::icase),
            regex(R"(\baesenclast\b)", regex_constants::icase),
            regex(R"(\baesdec\b)", regex_constants::icase),
            regex(R"(\baesdeclast\b)", regex_constants::icase),
            regex(R"(\baesimc\b)", regex_constants::icase),
            regex(R"(\baeskeygenassist\b)", regex_constants::icase),
            regex(R"(\bvaesenc\b)", regex_constants::icase),
            regex(R"(\bvaesenclast\b)", regex_constants::icase),
            regex(R"(\bvaesdec\b)", regex_constants::icase),
            regex(R"(\bvaesdeclast\b)", regex_constants::icase),
            regex(R"(\bpclmulqdq\b)", regex_constants::icase),
            regex(R"(\bvpclmulqdq\b)", regex_constants::icase),
            regex(R"(\bsha1rnds4\b)", regex_constants::icase),
            regex(R"(\bsha1nexte\b)", regex_constants::icase),
            regex(R"(\bsha1msg1\b)", regex_constants::icase),
            regex(R"(\bsha1msg2\b)", regex_constants::icase),
            regex(R"(\bsha256rnds2\b)", regex_constants::icase),
            regex(R"(\bsha256msg1\b)", regex_constants::icase),
            regex(R"(\bsha256msg2\b)", regex_constants::icase),
            regex(R"(\bsha512msg1\b)", regex_constants::icase),
            regex(R"(\bsha512msg2\b)", regex_constants::icase)
        }},
        {"Randomness / Entropy Instructions", {
            regex(R"(\brdrand\b)", regex_constants::icase),
            regex(R"(\brdseed\b)", regex_constants::icase),
            regex(R"(\brdpmc\b)", regex_constants::icase)
        }},
        {"Control-Flow Enforcement / Security Instructions", {
            regex(R"(\bendbr32\b)", regex_constants::icase),
            regex(R"(\bendbr64\b)", regex_constants::icase),
            regex(R"(\bwrss\b)", regex_constants::icase),
            regex(R"(\bwruss\b)", regex_constants::icase),
            regex(R"(\bincssp\b)", regex_constants::icase),
            regex(R"(\bsetssbsy\b)", regex_constants::icase),
            regex(R"(\brstorssp\b)", regex_constants::icase),
            regex(R"(\bsaveprevssp\b)", regex_constants::icase)
        }},
        {"Memory Protection / Bounds / Key Instructions", {
            regex(R"(\bbndmk\b)", regex_constants::icase),
            regex(R"(\bbndcl\b)", regex_constants::icase),
            regex(R"(\bbndcu\b)", regex_constants::icase),
            regex(R"(\bbndcn\b)", regex_constants::icase),
            regex(R"(\bbndldx\b)", regex_constants::icase),
            regex(R"(\bbndstx\b)", regex_constants::icase),
            regex(R"(\bbndmov\b)", regex_constants::icase),
            regex(R"(\bbndret\b)", regex_constants::icase),
            regex(R"(\bwrpkru\b)", regex_constants::icase),
            regex(R"(\brdpkru\b)", regex_constants::icase),
            regex(R"(\brdpkrus\b)", regex_constants::icase)
        }},
        {"Transactional / Speculation-Relevant Instructions", {
            regex(R"(\bxbegin\b)", regex_constants::icase),
            regex(R"(\bxend\b)", regex_constants::icase),
            regex(R"(\bxtest\b)", regex_constants::icase),
            regex(R"(\bxabort\b)", regex_constants::icase),
            regex(R"(\bclflush\b)", regex_constants::icase),
            regex(R"(\bclflushopt\b)", regex_constants::icase),
            regex(R"(\blfence\b)", regex_constants::icase),
            regex(R"(\bsfence\b)", regex_constants::icase),
            regex(R"(\bmfence\b)", regex_constants::icase)
        }},
        {"Stack / Frame Manipulation", {
            regex(R"(\bpush\b)", regex_constants::icase),
            regex(R"(\bpop\b)", regex_constants::icase),
            regex(R"(\bpushf\b|\bpushfd\b|\bpushfq\b)", regex_constants::icase),
            regex(R"(\bpopf\b|\bpopfd\b|\bpopfq\b)", regex_constants::icase),
            regex(R"(\bpusha\b|\bpushad\b)", regex_constants::icase),
            regex(R"(\bpopa\b|\bpopad\b)", regex_constants::icase),
            regex(R"(\benter\b)", regex_constants::icase),
            regex(R"(\bleave\b)", regex_constants::icase),
            regex(R"(\bmov\s+rbp\s*,\s*rsp\b)", regex_constants::icase),
            regex(R"(\bmov\s+ebp\s*,\s*esp\b)", regex_constants::icase),
            regex(R"(\bsub\s+rsp\s*,)", regex_constants::icase),
            regex(R"(\badd\s+rsp\s*,)", regex_constants::icase)
        }},
        {"Indirect Memory Access / Pointer Operations", {
            regex(R"(\bmov\s+[a-z0-9]+\s*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\bmov\s+\[.*\]\s*,\s*[a-z0-9]+)", regex_constants::icase),
            regex(R"(\blea\s+[a-z0-9]+\s*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\bcall\s+\[.*\])", regex_constants::icase),
            regex(R"(\bjmp\s+\[.*\])", regex_constants::icase),
            regex(R"(\bpush\s+\[.*\])", regex_constants::icase),
            regex(R"(\bpop\s+\[.*\])", regex_constants::icase),
            regex(R"(\bxchg\s+[a-z0-9]+\s*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\bcmpxchg\s+.*\[.*\])", regex_constants::icase),
            regex(R"(\bxadd\s+.*\[.*\])", regex_constants::icase)
        }},
        {"Suspicious Self-Modifying / Code-Modification Indicators", {
            regex(R"(\bmov\s+\[.*\]\s*,\s*[a-z0-9]+\b)", regex_constants::icase),
            regex(R"(\bstosb\b)", regex_constants::icase),
            regex(R"(\bstosw\b)", regex_constants::icase),
            regex(R"(\bstosd\b)", regex_constants::icase),
            regex(R"(\bstosq\b)", regex_constants::icase),
            regex(R"(\bxchg\s+.*,\s*\[.*\])", regex_constants::icase),
            regex(R"(\bcall\s+\[.*\])", regex_constants::icase),
            regex(R"(\bjmp\s+\[.*\])", regex_constants::icase)
        }},
        {"Dynamic Resolution / Loader / Execution Indicators", {
            regex(R"(\bcall\s+dlsym\b)", regex_constants::icase),
            regex(R"(\bcall\s+dlopen\b)", regex_constants::icase),
            regex(R"(\bcall\s+LoadLibrary\b)", regex_constants::icase),
            regex(R"(\bcall\s+GetProcAddress\b)", regex_constants::icase),
            regex(R"(\bcall\s+VirtualAlloc\b)", regex_constants::icase),
            regex(R"(\bcall\s+VirtualProtect\b)", regex_constants::icase),
            regex(R"(\bcall\s+mmap\b)", regex_constants::icase),
            regex(R"(\bcall\s+mprotect\b)", regex_constants::icase),
            regex(R"(\bcall\s+munmap\b)", regex_constants::icase)
        }},
        {"Executable Memory / Permission Changes", {
            regex(R"(\bcall\s+mprotect\b)", regex_constants::icase),
            regex(R"(\bcall\s+mmap\b)", regex_constants::icase),
            regex(R"(\bcall\s+VirtualProtect\b)", regex_constants::icase),
            regex(R"(\bcall\s+VirtualAlloc\b)", regex_constants::icase),
            regex(R"(\bPROT_EXEC\b)", regex_constants::icase),
            regex(R"(\bPAGE_EXECUTE\b)", regex_constants::icase),
            regex(R"(\bPAGE_EXECUTE_READ\b)", regex_constants::icase),
            regex(R"(\bPAGE_EXECUTE_READWRITE\b)", regex_constants::icase),
            regex(R"(\bPAGE_EXECUTE_WRITECOPY\b)", regex_constants::icase)
        }},
        {"Environment / Process / Command Execution Indicators", {
            regex(R"(\bcall\s+system\b)", regex_constants::icase),
            regex(R"(\bcall\s+popen\b)", regex_constants::icase),
            regex(R"(\bcall\s+execve\b)", regex_constants::icase),
            regex(R"(\bcall\s+execv\b)", regex_constants::icase),
            regex(R"(\bcall\s+execvp\b)", regex_constants::icase),
            regex(R"(\bcall\s+execl\b)", regex_constants::icase),
            regex(R"(\bcall\s+fork\b)", regex_constants::icase),
            regex(R"(\bcall\s+vfork\b)", regex_constants::icase),
            regex(R"(\bcall\s+clone\b)", regex_constants::icase),
            regex(R"(\bcall\s+CreateProcess\b)", regex_constants::icase),
            regex(R"(\bcall\s+WinExec\b)", regex_constants::icase),
            regex(R"(\bcall\s+ShellExecute\b)", regex_constants::icase)
        }},
        {"Security-Relevant Linux / Unix System Interfaces", {
            regex(R"(\bopen\b)", regex_constants::icase),
            regex(R"(\bopenat\b)", regex_constants::icase),
            regex(R"(\bread\b)", regex_constants::icase),
            regex(R"(\bwrite\b)", regex_constants::icase),
            regex(R"(\bclose\b)", regex_constants::icase),
            regex(R"(\bioctl\b)", regex_constants::icase),
            regex(R"(\bptrace\b)", regex_constants::icase),
            regex(R"(\bsetuid\b)", regex_constants::icase),
            regex(R"(\bsetgid\b)", regex_constants::icase),
            regex(R"(\bseteuid\b)", regex_constants::icase),
            regex(R"(\bsetegid\b)", regex_constants::icase),
            regex(R"(\bsetresuid\b)", regex_constants::icase),
            regex(R"(\bsetresgid\b)", regex_constants::icase),
            regex(R"(\bchmod\b)", regex_constants::icase),
            regex(R"(\bfchmod\b)", regex_constants::icase),
            regex(R"(\bchown\b)", regex_constants::icase),
            regex(R"(\bfchown\b)", regex_constants::icase),
            regex(R"(\bmount\b)", regex_constants::icase),
            regex(R"(\bumount\b)", regex_constants::icase)
        }},
        {"Windows Security-Relevant System Interfaces", {
            regex(R"(\bNtWriteVirtualMemory\b)", regex_constants::icase),
            regex(R"(\bWriteProcessMemory\b)", regex_constants::icase),
            regex(R"(\bReadProcessMemory\b)", regex_constants::icase),
            regex(R"(\bVirtualAlloc\b)", regex_constants::icase),
            regex(R"(\bVirtualAllocEx\b)", regex_constants::icase),
            regex(R"(\bVirtualProtect\b)", regex_constants::icase),
            regex(R"(\bVirtualProtectEx\b)", regex_constants::icase),
            regex(R"(\bCreateRemoteThread\b)", regex_constants::icase),
            regex(R"(\bOpenProcess\b)", regex_constants::icase),
            regex(R"(\bOpenThread\b)", regex_constants::icase),
            regex(R"(\bSetThreadContext\b)", regex_constants::icase),
            regex(R"(\bGetThreadContext\b)", regex_constants::icase),
            regex(R"(\bCreateProcess\b)", regex_constants::icase),
            regex(R"(\bWinExec\b)", regex_constants::icase)
        }},
        {"Debugging / Tracing / Instrumentation", {
            regex(R"(\bint3\b)", regex_constants::icase),
            regex(R"(\bint\s+3\b)", regex_constants::icase),
            regex(R"(\bicebp\b)", regex_constants::icase),
            regex(R"(\bdr0\b|\bdr1\b|\bdr2\b|\bdr3\b)", regex_constants::icase),
            regex(R"(\bdr6\b|\bdr7\b)", regex_constants::icase),
            regex(R"(\bptrace\b)", regex_constants::icase),
            regex(R"(\brdpmc\b)", regex_constants::icase),
            regex(R"(\brdtsc\b)", regex_constants::icase),
            regex(R"(\brdtscp\b)", regex_constants::icase),
            regex(R"(\bcpuid\b)", regex_constants::icase)
        }},
        {"CPU Identification / Feature Detection", {
            regex(R"(\bcpuid\b)", regex_constants::icase),
            regex(R"(\bxgetbv\b)", regex_constants::icase),
            regex(R"(\bxsetbv\b)", regex_constants::icase),
            regex(R"(\bgetsec\b)", regex_constants::icase),
            regex(R"(\bclac\b)", regex_constants::icase),
            regex(R"(\bstac\b)", regex_constants::icase)
        }},
        {"Architecture / Segment / Addressing Indicators", {
            regex(R"(\bcs\b)", regex_constants::icase),
            regex(R"(\bds\b)", regex_constants::icase),
            regex(R"(\bes\b)", regex_constants::icase),
            regex(R"(\bfs\b)", regex_constants::icase),
            regex(R"(\bgs\b)", regex_constants::icase),
            regex(R"(\bss\b)", regex_constants::icase),
            regex(R"(\bfsbase\b)", regex_constants::icase),
            regex(R"(\bgsbase\b)", regex_constants::icase),
            regex(R"(\bwrfsbase\b)", regex_constants::icase),
            regex(R"(\bwrgsbase\b)", regex_constants::icase),
            regex(R"(\brdfsbase\b)", regex_constants::icase),
            regex(R"(\brdgsbase\b)", regex_constants::icase)
        }}
    };
}
// Execute objdump (disassemble) on a binary
// returns disassembly output or throws runtime_error on failure
string exec_objdump(const string& binary_path, bool verbose) {
    // Check objdump exists by trying `objdump --version` (quietly)
    {
        array<char, 256> chkbuf{};
        const string chkcmd = "objdump --version 2>/dev/null";
        unique_ptr<FILE, decltype(&pclose)> chkpipe(popen(chkcmd.c_str(), "r"), pclose);
        if (!chkpipe) {
            throw runtime_error("popen() failed when checking objdump availability");
        }
        bool any = false;
        while (fgets(chkbuf.data(), static_cast<int>(chkbuf.size()), chkpipe.get()) != nullptr) {
            any = true;
        }
        if (!any) {
            throw runtime_error("objdump not found or not functioning. Please install binutils (objdump).");
        }
    }
    array<char, 256> buffer{};
    string result;
    const string cmd = "objdump -d \"" + binary_path + "\" 2>/dev/null";
    if (verbose) {
        cerr << "[DEBUG] Running: " << cmd << "\n";
    }
    unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw runtime_error("popen() failed when running objdump!");
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    if (result.empty()) {
        throw runtime_error("objdump produced no output (binary may be invalid or objdump failed).");
    }
    return result;
}
// Scan asm text with pattern groups (parallelized but with limited concurrency)
vector<string> scan_asm_text(
    const string& asm_text,
    const vector<PatternGroup>& pattern_groups,
    const string& source_name = "asm_text",
    size_t max_workers = 0,
    bool verbose = false
) {
    vector<string> results;
    set<string> seen_issues;
    mutex seen_mutex;
    mutex results_mutex;
    // Determine max_workers if not provided
    if (max_workers == 0) {
        const unsigned int hc = thread::hardware_concurrency();
        max_workers = (hc == 0) ? 4u : max<size_t>(1u, hc);
    }
    if (verbose) {
        cerr << "[DEBUG] Using up to " << max_workers << " worker(s) for scanning.\n";
    }
    istringstream iss(asm_text);
    string line;
    size_t line_number = 0;
    vector<future<vector<string>>> active_futures;
    active_futures.reserve(max_workers * 2);
    const regex whitespace_regex(R"(\s+)");
    auto launch_task = [&](string line_copy, size_t ln) -> future<vector<string>> {
        return async(
            launch::async,
            [line_copy = move(line_copy), ln, &pattern_groups, &seen_issues, &seen_mutex, &source_name, &whitespace_regex]() -> vector<string> {
                vector<string> local_results;
                string normalized_line = regex_replace(line_copy, whitespace_regex, " ");
                for (const auto& group : pattern_groups) {
                    for (const auto& re : group.patterns) {
                        if (regex_search(normalized_line, re)) {
                            string issue_identifier =
                                group.name + ":" + to_string(ln) + ":" + normalized_line;
                            bool should_add = false;
                            {
                                lock_guard<mutex> lg(seen_mutex);
                                if (seen_issues.find(issue_identifier) == seen_issues.end()) {
                                    seen_issues.insert(issue_identifier);
                                    should_add = true;
                                }
                            }
                            if (should_add) {
                                local_results.push_back(
                                    "[" + group.name + "] " +
                                    source_name + ":" +
                                    to_string(ln) + ": " +
                                    line_copy
                                );
                            }
                        }
                    }
                }
                return local_results;
            }
        );
    };
    while (getline(iss, line)) {
        ++line_number;
        while (active_futures.size() >= max_workers) {
            auto& f = active_futures.front();
            try {
                auto r = f.get();
                if (!r.empty()) {
                    lock_guard<mutex> lg(results_mutex);
                    results.insert(
                        results.end(),
                        make_move_iterator(r.begin()),
                        make_move_iterator(r.end())
                    );
                }
            }
            catch (...) {}
            active_futures.erase(active_futures.begin());
        }
        active_futures.push_back(launch_task(move(line), line_number));
    }
    for (auto& f : active_futures) {
        try {
            auto r = f.get();
            if (!r.empty()) {
                lock_guard<mutex> lg(results_mutex);
                results.insert(
                    results.end(),
                    make_move_iterator(r.begin()),
                    make_move_iterator(r.end())
                );
            }
        }
        catch (...) {}
    }
    return results;
}
int main(int argc, char** argv) {
    if (argc < 3) {
        cerr << "Usage:\n"
             << "  asm_scanner --asm <asm_file_path> [--verbose] [--log <log_file>]\n"
             << "  asm_scanner --bin <binary_file_path> [--verbose] [--log <log_file>]\n";
        return 1;
    }
    string mode;
    string path;
    bool verbose = false;
    string log_path;
    vector<string> args(argv + 1, argv + argc);
    mode = args.size() > 0 ? args[0] : "";
    if (args.size() > 1) path = args[1];
    for (size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--verbose") {
            verbose = true;
        }
        else if (args[i] == "--log") {
            if (i + 1 < args.size()) {
                log_path = args[i + 1];
                ++i;
            }
            else {
                cerr << "Error: --log requires a file path argument\n";
                return 1;
            }
        }
        else if (args[i] == "--help" || args[i] == "-h") {
            cerr << "Usage:\n"
                 << "  asm_scanner --asm <asm_file_path> [--verbose] [--log <log_file>]\n"
                 << "  asm_scanner --bin <binary_file_path> [--verbose] [--log <log_file>]\n";
            return 0;
        }
        else {
            if (!args[i].empty() && args[i][0] == '-') {
                cerr << "Warning: Unknown flag '" << args[i] << "' ignored.\n";
            }
        }
    }
    if (mode.empty() || path.empty()) {
        cerr << "Error: mode and path required.\n";
        return 1;
    }
    vector<PatternGroup> patterns = get_asm_vuln_patterns();
    vector<string> issues;
    ofstream log_ofs;
    bool log_enabled = false;
    if (!log_path.empty()) {
        log_ofs.open(log_path, ios::out | ios::trunc);
        if (!log_ofs) {
            cerr << "Error: Could not open log file: " << log_path << "\n";
            return 1;
        }
        log_enabled = true;
    }
    try {
        if (mode == "--asm") {
            ifstream file(path);
            if (!file) {
                cerr << "Error opening asm file: " << path << endl;
                return 1;
            }
            string asm_text;
            {
                ostringstream ss;
                ss << file.rdbuf();
                asm_text = ss.str();
            }
            const unsigned int hc = thread::hardware_concurrency();
            const size_t workers = (hc == 0) ? 4u : max<size_t>(1u, hc);
            issues = scan_asm_text(asm_text, patterns, path, workers, verbose);
        }
        else if (mode == "--bin") {
            if (!fs::exists(path)) {
                cerr << "Error: Binary file does not exist: " << path << "\n";
                return 1;
            }
            string asm_text = exec_objdump(path, verbose);
            const unsigned int hc = thread::hardware_concurrency();
            const size_t workers = (hc == 0) ? 4u : max<size_t>(1u, hc);
            issues = scan_asm_text(asm_text, patterns, path, workers, verbose);
        }
        else {
            cerr << "Unknown mode: " << mode << "\n";
            cerr << "Use --asm or --bin\n";
            return 1;
        }
        if (issues.empty()) {
            cout << " No potential vulnerabilities found.\n";
            if (log_enabled) log_ofs << " No potential vulnerabilities found.\n";
        }
        else {
            cout << " Potential vulnerabilities detected:\n";
            if (log_enabled) log_ofs << " Potential vulnerabilities detected:\n";
            for (const auto& issue : issues) {
                cout << issue << "\n";
                if (log_enabled) log_ofs << issue << "\n";
            }
        }
    }
    catch (const exception& e) {
        cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
} //g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -pthread cves_asm.1.0.cpp -o asm_scan
