// Rule engine interface (multi-condition, type-scoped, regex capable)
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <regex>
#include "Scanner.h"

namespace sys_scan {

struct RuleCondition {
    std::string field;      // id|title|description or metadata key (empty => description)
    std::string contains;   // substring constraint
    std::string equals;     // exact match constraint
    std::string regex;      // regex pattern (ECMAScript)
    std::optional<std::regex> compiled; // precompiled regex if valid
};

struct Rule {
    std::string id;
    std::string scope;              // optional: scanner name (e.g. "network", "world_writable") or * for all
    std::vector<RuleCondition> conditions; // all or any depending on logic_any
    bool logic_any = false;         // true => any condition; false => all
    std::string severity_override;  // new name (legacy severity still accepted)
    std::string mitre;              // MITRE technique IDs (comma separated)
    int version = 1;                // rule schema version (default 1)
    // Backward compatibility single-condition fields retained during parse only
    std::string legacy_field; 
    std::string legacy_contains; 
    std::string legacy_equals;
    std::string legacy_regex;
};

// Structured warning emitted during rule loading. Replaces legacy flat string while
// retaining backward-compatible aggregated string returned by load_dir().
struct RuleWarning {
    std::string rule_id;   // may be empty for directory/global issues
    std::string code;      // e.g. unsupported_version, bad_regex, no_conditions, rules_dir_missing
    std::string detail;    // optional detail (e.g. provided version, regex pattern)
};

class RuleEngine {
public:
    void load_dir(const std::string& dir, std::string& warning_out);
    void apply(const std::string& scanner, Finding& f) const; // mutate finding in place
    const std::vector<RuleWarning>& warnings() const { return warnings_; }
    // Helper to rebuild legacy aggregated warning string format (id:code[=detail];...)
    std::string warnings_aggregated() const;
    // Guardrail configuration (hard-coded for now; could be made configurable later)
    static constexpr size_t MAX_RULES = 1000;
    static constexpr size_t MAX_CONDITIONS_PER_RULE = 25;
    static constexpr size_t MAX_REGEX_LENGTH = 512; // characters
private:
    std::vector<Rule> rules_;
    std::vector<RuleWarning> warnings_;
};

RuleEngine& rule_engine();

}
