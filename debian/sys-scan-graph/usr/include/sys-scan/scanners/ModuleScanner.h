#pragma once
#include "../core/Scanner.h"
#include "../core/ScanContext.h"
namespace sys_scan { class ModuleScanner : public Scanner { public: std::string name() const override { return "modules"; } std::string description() const override { return "List loaded kernel modules"; } void scan(ScanContext& context) override; }; }
