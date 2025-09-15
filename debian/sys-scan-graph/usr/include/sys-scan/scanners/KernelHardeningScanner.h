#pragma once
#include "../core/Scanner.h"

namespace sys_scan {

// Forward declaration to avoid circular includes
struct ScanContext;

class KernelHardeningScanner : public Scanner {
public:
    std::string name() const override { return "kernel_hardening"; }
    std::string description() const override { return "Checks kernel and platform hardening state (lockdown, secure boot, IMA, TPM, sysctls)"; }
    void scan(ScanContext& context) override;
};

}
