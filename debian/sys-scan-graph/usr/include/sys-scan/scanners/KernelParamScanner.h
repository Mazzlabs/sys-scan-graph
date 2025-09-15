#pragma once
#include "../core/Scanner.h"
#include <string>
#include <vector>

namespace sys_scan {

class KernelParamScanner : public Scanner {
public:
    std::string name() const override { return "kernel_params"; }
    std::string description() const override { return "Check security-relevant kernel parameters"; }
    void scan(ScanContext& context) override;
};

}
