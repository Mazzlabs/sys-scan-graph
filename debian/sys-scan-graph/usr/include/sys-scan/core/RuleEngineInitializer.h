#pragma once

#include "core/Config.h"
#include "core/RuleEngine.h"
#include <string>
#include <filesystem>
#include <unordered_set>

namespace sys_scan {

class RuleEngineInitializer {
public:
    RuleEngineInitializer() = default;
    ~RuleEngineInitializer() = default;

    // Initialize rule engine if enabled
    bool initialize(const Config& cfg);

private:
    bool validate_rules_directory(const std::string& path) const;
    bool check_legacy_rules() const;
    bool validate_rule_files(const std::string& dir) const;
    bool validate_single_rule_file(const std::filesystem::path& file_path, std::unordered_set<std::string>& rule_names) const;
};

} // namespace sys_scan