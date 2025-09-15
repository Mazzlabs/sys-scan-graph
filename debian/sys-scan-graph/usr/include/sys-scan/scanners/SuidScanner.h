#pragma once
#include "../core/Scanner.h"
#include "../core/ScanContext.h"

namespace sys_scan {
class SuidScanner : public Scanner {
public:
    std::string name() const override { return "suid_sgid"; }
    std::string description() const override { return "Find SUID/SGID binaries"; }
    void scan(ScanContext& context) override;
};
}
