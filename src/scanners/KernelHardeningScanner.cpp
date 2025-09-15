#include "KernelHardeningScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <sys/stat.h>
#include <unistd.h>

namespace sys_scan {

static std::string read_first_line(const char* path){ std::ifstream f(path); if(!f.is_open()) return {}; std::string line; std::getline(f,line); return line; }
static bool file_exists(const char* p){ return access(p, F_OK)==0; }
static std::string read_all(const char* path){ std::ifstream f(path); if(!f.is_open()) return {}; std::ostringstream ss; ss<<f.rdbuf(); return ss.str(); }

void KernelHardeningScanner::scan(ScanContext& context){
    if(!context.config.hardening) return;

    // Start scanner
    context.report.start_scanner(name());

    // Lockdown status (since Linux 5.4) /sys/kernel/security/lockdown shows e.g. "none [integrity] confidentiality"
    {
        std::string root = context.config.test_root.empty() ? "" : context.config.test_root;
        std::string lockdown_path = root + "/sys/kernel/security/lockdown";
        std::string lockdown = read_first_line(lockdown_path.c_str());
        if(!lockdown.empty()){
            // Determine active lockdown mode: token with brackets
            size_t lb = lockdown.find('['); size_t rb = lockdown.find(']');
            std::string active;
            if(lb!=std::string::npos && rb!=std::string::npos && rb>lb) active = lockdown.substr(lb+1, rb-lb-1);
            if(active.empty() || active=="none"){
                Finding f; f.id="kernel:lockdown:disabled"; f.title="Kernel lockdown inactive"; f.severity=Severity::Medium; f.description="Kernel lockdown not enforced; consider integrity or confidentiality mode"; f.metadata["raw"] = lockdown; context.report.add_finding(name(), std::move(f));
            } else if(active=="integrity"){
                Finding f; f.id="kernel:lockdown:integrity"; f.title="Kernel lockdown integrity mode"; f.severity=Severity::Info; f.description="Kernel lockdown integrity mode active"; f.metadata["raw"] = lockdown; context.report.add_finding(name(), std::move(f));
            } else if(active=="confidentiality"){
                Finding f; f.id="kernel:lockdown:confidentiality"; f.title="Kernel lockdown confidentiality mode"; f.severity=Severity::Info; f.description="Kernel lockdown confidentiality mode active"; f.metadata["raw"] = lockdown; context.report.add_finding(name(), std::move(f));
            }
        }
    }

    // Secure Boot indication (presence of EFI vars + mokutil style paths). Simplified heuristic.
    {
        std::string root = context.config.test_root.empty() ? "" : context.config.test_root;
        std::string efi_path = root + "/sys/firmware/efi";
        if(file_exists(efi_path.c_str())){
            // dbx revocation list presence - check for any dbx files in efivars
            bool have_dbx = false;
            // Check for common dbx file patterns
            std::vector<std::string> dbx_paths = {
                root + "/sys/firmware/efi/efivars/dbx",
                root + "/sys/firmware/efi/efivars/dbx-default"
            };
            for(const auto& dbx_path : dbx_paths) {
                if(file_exists(dbx_path.c_str())) {
                    have_dbx = true;
                    break;
                }
            }
            Finding f; f.id = "kernel:secureboot:efi"; f.title = "EFI firmware detected"; f.severity=Severity::Info; f.description = "System booted with EFI (secure boot state heuristic)"; f.metadata["efi"]="present"; context.report.add_finding(name(), std::move(f));
            if(!have_dbx){ Finding f2; f2.id="kernel:secureboot:dbx-missing"; f2.title="EFI dbx revocation list not detected"; f2.severity=Severity::Low; f2.description="Could not locate dbx revocation entries (heuristic)"; context.report.add_finding(name(), std::move(f2)); }
        }
    }

    // IMA/EVM appraisal: check securityfs
    {
        std::string root = context.config.test_root.empty() ? "" : context.config.test_root;
        std::string ima_policy_path = root + "/sys/kernel/security/ima/policy";
        std::string ima_policy = read_all(ima_policy_path.c_str());
        if(!ima_policy.empty()){
            bool has_appraise = ima_policy.find("appraise")!=std::string::npos;
            Finding f; f.id="kernel:ima:policy"; f.title="IMA policy present"; f.severity=Severity::Info; f.description = has_appraise?"IMA policy includes appraisal":"IMA policy lacks explicit appraisal"; f.metadata["appraise"] = has_appraise?"yes":"no"; context.report.add_finding(name(), std::move(f));
        }
    }

    // TPM presence
    {
        std::string root = context.config.test_root.empty() ? "" : context.config.test_root;
        if(file_exists((root + "/dev/tpm0").c_str()) || file_exists((root + "/dev/tpmrm0").c_str())){
            Finding f; f.id="kernel:tpm:present"; f.title="TPM device present"; f.severity=Severity::Info; f.description="Trusted Platform Module detected"; context.report.add_finding(name(), std::move(f));
        } else {
            Finding f; f.id="kernel:tpm:absent"; f.title="No TPM device"; f.severity=Severity::Low; f.description="TPM not detected (may reduce attestation options)"; context.report.add_finding(name(), std::move(f));
        }
    }

    // Security-relevant sysctls (read /proc/sys/...)
    auto read_sysctl = [&](const std::string& path)->std::string{
        std::string root = context.config.test_root.empty() ? "" : context.config.test_root;
        return read_first_line((root + path).c_str());
    };
    struct SysctlCheck { const char* path; const char* id; const char* title; const char* expect; Severity sev; const char* bad_desc; const char* good_desc; };
    std::vector<SysctlCheck> checks = {
        {"/proc/sys/kernel/kptr_restrict","sysctl:kptr_restrict","kptr_restrict", "1", Severity::Low, "Kernel pointers not restricted", "Kernel pointers restricted"},
        {"/proc/sys/kernel/dmesg_restrict","sysctl:dmesg_restrict","dmesg_restrict", "1", Severity::Low, "dmesg not restricted", "dmesg restricted"},
        {"/proc/sys/kernel/kexec_load_disabled","sysctl:kexec_disabled","kexec disabled", "1", Severity::Medium, "kexec not disabled", "kexec disabled"},
        {"/proc/sys/kernel/sysrq","sysctl:sysrq","sysrq controls", "0", Severity::Low, "sysrq not fully disabled", "sysrq disabled"},
        {"/proc/sys/net/ipv4/tcp_syncookies","sysctl:tcp_syncookies","tcp_syncookies", "1", Severity::Low, "tcp_syncookies off", "tcp_syncookies on"},
        {"/proc/sys/net/ipv4/conf/all/rp_filter","sysctl:rp_filter","rp_filter", "1", Severity::Low, "rp_filter not strict", "rp_filter strict"},
        {"/proc/sys/net/ipv4/conf/all/accept_redirects","sysctl:accept_redirects","accept_redirects", "0", Severity::Low, "ICMP redirects accepted", "ICMP redirects blocked"},
        {"/proc/sys/net/ipv4/conf/all/accept_source_route","sysctl:accept_source_route","accept_source_route", "0", Severity::Low, "Source routed packets accepted", "Source routed packets blocked"},
    };
    for(const auto& c : checks){
        std::string val = read_sysctl(c.path); if(val.empty()) continue; // skip if not present
        // trim whitespace
        while(!val.empty() && (val.back()=='\n' || val.back()=='\r' || val.back()==' ')) val.pop_back();
        Finding f; f.id = std::string("kernel:") + c.id; f.title = c.title; f.metadata["path"] = c.path; f.metadata["value"] = val; f.metadata["expected"] = c.expect; if(val==c.expect){ f.severity=Severity::Info; f.description=c.good_desc; } else { f.severity=c.sev; f.description=c.bad_desc; } context.report.add_finding(name(), std::move(f));
    }

    // End scanner
    context.report.end_scanner(name());
}

}
