#pragma once

#include "core/Report.h"
#include "core/Config.h"
#include "core/JSONWriter.h"
#include <string>
#include <fstream>

namespace sys_scan {

class OutputWriter {
public:
    OutputWriter() = default;
    ~OutputWriter() = default;

    // Write report to output destination
    bool write_report(const Report& report, const Config& cfg);

    // Write environment file
    bool write_env_file(const Config& cfg);

private:
    JSONWriter json_writer_;
    std::string format_json(const std::string& json, const Config& cfg) const;
};

} // namespace sys_scan