#pragma once
#include "../core/Scanner.h"
#include <unordered_map>

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

struct ContainerInfo {
    std::string id; // truncated id or synthesized namespace hash
    std::string runtime; // docker|containerd|podman|crio|unknown
    std::string cgroup_path;
    std::string pid_example;
};

class ContainerScanner : public Scanner {
public:
    std::string name() const override { return "containers"; }
    std::string description() const override { return "Detects containerized contexts via cgroups and runtime markers"; }
    void scan(ScanContext& context) override;
    static std::string derive_container_id(const std::string& cg);
};

}
