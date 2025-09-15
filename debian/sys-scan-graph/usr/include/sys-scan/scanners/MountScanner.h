#pragma once
#include "../core/Scanner.h"
#include <vector>

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

class MountScanner : public Scanner {
public:
    std::string name() const override { return "mounts"; }
    std::string description() const override { return "Checks mount options and surfaces risky configurations"; }
    void scan(ScanContext& context) override;
};

}
