#pragma once
#include "Scanner.h"
#include "ScanContext.h"
#include <vector>

namespace sys_scan {

class ScannerRegistry {
public:
    void register_scanner(ScannerPtr scanner);
    void register_all_default(const Config& config);
    void run_all(ScanContext& context); // Updated to accept ScanContext
private:
    void run_all_sequential(ScanContext& context); // Updated to accept ScanContext
    void run_all_parallel(ScanContext& context);   // Updated to accept ScanContext
private:
    std::vector<ScannerPtr> scanners_;
};

}
