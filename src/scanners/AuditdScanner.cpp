#include "AuditdScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include <fstream>
#include <filesystem>
#include <regex>
#include <unordered_set>
#include <sstream>

namespace sys_scan {
namespace fs = std::filesystem;

static std::string read_all(const fs::path& p){ std::ifstream f(p); if(!f.is_open()) return {}; std::ostringstream ss; ss<<f.rdbuf(); return ss.str(); }

void AuditdScanner::scan(ScanContext& context){
    if(!context.config.hardening) return;

    // Start scanner
    context.report.start_scanner(name());

    // Collect audit rules from /etc/audit/rules.d/*.rules and /etc/audit/audit.rules
    std::vector<fs::path> paths;
    std::string root = context.config.test_root.empty() ? "" : context.config.test_root;
    fs::path audit_rules = fs::path(root) / "etc/audit/audit.rules";
    fs::path rules_dir = fs::path(root) / "etc/audit/rules.d";

    if(fs::exists(audit_rules)) paths.push_back(audit_rules);
    if(fs::exists(rules_dir)){
        for(auto& e : fs::directory_iterator(rules_dir)){
            if(e.is_regular_file() && e.path().extension()==".rules") paths.push_back(e.path());
        }
    }
    std::string combined;
    for(const auto& p : paths){ combined += read_all(p); combined += "\n"; }
    if(combined.empty()){
        Finding f; f.id="auditd:rules:missing"; f.title="No auditd rules detected"; f.severity=Severity::Medium; f.description="Could not read auditd rules files"; context.report.add_finding(name(), std::move(f));
        context.report.end_scanner(name());
        return;
    }

    // Basic heuristics: look for execve (-S execve), setuid/setgid, chmod/chown, module loading, sudo/su, CAP_SYS_ADMIN, privilege escalation events.
    struct Pattern { const char* id; const char* regex_str; const char* title; const char* desc; Severity sev; };
    std::vector<Pattern> pats = {
        {"execve", "-S\\s+execve", "Audit execve present", "Execve syscall auditing present", Severity::Info},
        {"setuid", "-S\\s+setuid", "Audit setuid present", "setuid syscall auditing present", Severity::Info},
        {"setgid", "-S\\s+setgid", "Audit setgid present", "setgid syscall auditing present", Severity::Info},
        {"chmod", "-S\\s+chmod", "Audit chmod present", "chmod syscall auditing present", Severity::Info},
        {"chown", "-S\\s+chown", "Audit chown present", "chown syscall auditing present", Severity::Info},
        {"capset", "-S\\s+capset", "Audit capset present", "capset syscall auditing present", Severity::Info},
        {"insmod", "-k\\s*modules|/s?bin/(insmod|modprobe)", "Module load auditing", "Module load operations likely audited", Severity::Info},
    };

    std::unordered_set<std::string> matched;
    for(const auto& p : pats){
        try {
            std::regex rgx(p.regex_str, std::regex::icase);
            if(std::regex_search(combined, rgx)) matched.insert(p.id);
        } catch(...) { /* ignore invalid regex */ }
    }

    for(const auto& p : pats){
        bool ok = matched.count(p.id);
        Finding f; f.id = std::string("auditd:") + p.id; f.title = p.title; f.description = ok ? p.desc : (std::string(p.title) + " missing"); f.severity = ok ? Severity::Info : Severity::Medium; context.report.add_finding(name(), std::move(f));
    }

    // Execve coverage absence escalated severity
    if(!matched.count("execve")){
        Finding f; f.id="auditd:execve:absent"; f.title="Execve auditing missing"; f.severity=Severity::High; f.description="Audit rules lack -S execve; process execution coverage incomplete"; context.report.add_finding(name(), std::move(f));
    }

    // End scanner
    context.report.end_scanner(name());
}

}
