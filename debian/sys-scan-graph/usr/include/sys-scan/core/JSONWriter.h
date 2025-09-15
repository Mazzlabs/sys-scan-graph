#pragma once
#include <string>
#include "Report.h"
#include "Config.h"

namespace sys_scan {
class JSONWriter {
public:
    std::string write(const Report& report, const Config& cfg) const;
};
}
