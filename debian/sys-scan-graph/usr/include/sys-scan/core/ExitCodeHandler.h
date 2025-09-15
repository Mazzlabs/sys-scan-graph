#pragma once

#include "core/Report.h"
#include "core/Config.h"

namespace sys_scan {

class ExitCodeHandler {
public:
    ExitCodeHandler() = default;
    ~ExitCodeHandler() = default;

    // Calculate exit code based on findings and configuration
    int calculate_exit_code(const Report& report, const Config& cfg) const;

private:
    int severity_rank(const std::string& severity) const;
    int severity_rank_enum(Severity severity) const;
};

} // namespace sys_scan