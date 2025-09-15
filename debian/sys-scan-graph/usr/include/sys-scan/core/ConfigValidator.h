#pragma once

#include "core/Config.h"
#include <string>
#include <vector>

namespace sys_scan {

class ConfigValidator {
public:
    ConfigValidator() = default;
    ~ConfigValidator() = default;

    // Validate configuration after parsing
    bool validate(Config& cfg);

    // Apply fast-scan optimizations
    void apply_fast_scan_optimizations(Config& cfg);

    // Load external files (IOC allowlist, SUID expected)
    bool load_external_files(Config& cfg);

private:
    bool validate_severity(const std::string& severity, const std::string& flag_name);
    int severity_rank(const std::string& severity) const;
    bool load_ioc_allowlist(Config& cfg);
    bool load_suid_expected(Config& cfg);
    std::vector<std::string> allowed_severities_ = {"info", "low", "medium", "high", "critical", "error"};
};

} // namespace sys_scan