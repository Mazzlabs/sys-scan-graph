#pragma once
#include "../core/Scanner.h"

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

class MACScanner : public Scanner {
public:
    std::string name() const override { return "mac"; }
    std::string description() const override { return "Mandatory Access Control (SELinux/AppArmor) status"; }
    void scan(ScanContext& context) override;
};
}
