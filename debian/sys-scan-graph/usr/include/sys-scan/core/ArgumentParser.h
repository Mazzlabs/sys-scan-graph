#pragma once

#include "core/Config.h"
#include <vector>
#include <string>
#include <functional>

namespace sys_scan {

class ArgumentParser {
public:
    struct FlagSpec {
        const char* name;
        enum class ArgKind { None, String, Int, CSV, OptionalInt } kind;
        std::function<void(const std::string&)> apply;
    };

    ArgumentParser();
    ~ArgumentParser() = default;

    // Parse command line arguments and apply them to config
    bool parse(int argc, char** argv, Config& cfg);

    // Print help message
    void print_help() const;

    // Print version information
    void print_version() const;

private:
    std::vector<FlagSpec> specs_;
    std::vector<std::string> split_csv(const std::string& s) const;
    int need_int(const std::string& v, const char* flag) const;
    FlagSpec* find_spec(const std::string& flag);
};

} // namespace sys_scan