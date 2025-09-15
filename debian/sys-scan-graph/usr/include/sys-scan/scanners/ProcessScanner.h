#pragma once
#include "../core/Scanner.h"

namespace sys_scan {
class ProcessScanner : public Scanner {
public:
    std::string name() const override { return "processes"; }
    std::string description() const override { return "Enumerate running processes with uid, gid, cmdline"; }
    void scan(ScanContext& context) override;
};
}
