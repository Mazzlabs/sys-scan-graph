
#include "ContainerScanner.h"
#include "../core/ScanContext.h"
#include "../core/Report.h"
#include "../core/Config.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <cctype>
#include <algorithm>

namespace fs = std::filesystem;
namespace sys_scan {

// Implement static helper declared in the header
std::string ContainerScanner::derive_container_id(const std::string& cg) {
    // Fast scan for a 64- or 32-char hex sequence; return first 12 chars as short id
    const char* s = cg.c_str();
    size_t n = cg.size();
    size_t i = 0;
    auto is_hex = [](unsigned char c)->bool{
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    };
    while (i < n) {
        // Skip non-hex
        while (i < n && !is_hex((unsigned char)s[i])) ++i;
        if (i >= n) break;
        // Count contiguous hex run
        size_t start = i;
        while (i < n && is_hex((unsigned char)s[i])) ++i;
        size_t run = i - start;
        // Prefer 64, then 32
        if (run >= 64) {
            return cg.substr(start, 12);
        }
        if (run >= 32) {
            return cg.substr(start, 12);
        }
        // Otherwise continue scanning
    }
    return {};
}

void ContainerScanner::scan(ScanContext& context) {
    const auto& cfg = context.config;
    if (!cfg.containers) return;

    // Start scanner
    context.report.start_scanner(name());

    // Map container id -> info
    std::unordered_map<std::string, ContainerInfo> cmap;

    std::string proc_path = cfg.test_root.empty() ? "/proc" : cfg.test_root + "/proc";
    for (const auto& entry : fs::directory_iterator(proc_path, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_directory()) continue;
        auto pid = entry.path().filename().string();
        if (!std::all_of(pid.begin(), pid.end(), ::isdigit)) continue;

        std::ifstream cgfs(entry.path().string() + "/cgroup");
        if (!cgfs) continue;

        std::string line;
        bool attributed = false;
        bool saw_kubepods = false;
        std::string kubepods_line;

        while (std::getline(cgfs, line)) {
            if (!saw_kubepods && line.find("kubepods") != std::string::npos) {
                saw_kubepods = true;
                kubepods_line = line;
            }
            auto id = derive_container_id(line);
            if (!id.empty()) {
                auto& ci = cmap[id];
                ci.id = id;
                if (ci.pid_example.empty()) ci.pid_example = pid;
                ci.cgroup_path = line;
                if (line.find("docker") != std::string::npos) ci.runtime = "docker";
                else if (line.find("containerd") != std::string::npos) ci.runtime = "containerd";
                else if (line.find("podman") != std::string::npos || line.find("libpod") != std::string::npos) ci.runtime = "podman";
                else if (line.find("crio") != std::string::npos) ci.runtime = "crio";
                else ci.runtime = "unknown";
                attributed = true;
                break;
            }
        }

        if (!attributed && saw_kubepods) {
            auto& ci = cmap["kubepods"];
            ci.id = "kubepods";
            if (ci.pid_example.empty()) ci.pid_example = pid;
            ci.runtime = "kube";
            ci.cgroup_path = kubepods_line;
        }
    }

    for (auto& [id, ci] : cmap) {
        Finding f;
        f.id = "container:" + id;
        f.title = "Container detected " + id;
        f.severity = Severity::Info;
        f.description = "Container runtime context";
        f.metadata["runtime"] = ci.runtime;
        f.metadata["pid"] = ci.pid_example;
        f.metadata["cgroup"] = ci.cgroup_path;
        context.report.add_finding(name(), std::move(f));
    }
    if (cmap.empty()) {
        Finding f;
        f.id = "container:none";
        f.title = "No containers detected";
        f.severity = Severity::Info;
        f.description = "No container cgroup signatures found";
        context.report.add_finding(name(), std::move(f));
    }

    // End scanner
    context.report.end_scanner(name());
}

} // namespace sys_scan
