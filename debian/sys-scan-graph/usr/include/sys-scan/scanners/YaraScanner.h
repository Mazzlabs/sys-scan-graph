#pragma once
#include "../core/Scanner.h"
#include <vector>
#include <string>

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

class YaraScanner : public Scanner {
public:
    std::string name() const override { return "yara"; }
    std::string description() const override { return "YARA rule matching over selected filesystem roots"; }
    void scan(ScanContext& context) override;
};

}
