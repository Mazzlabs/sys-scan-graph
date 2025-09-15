#pragma once
#include "../core/Scanner.h"
#include "../core/ScanContext.h"
namespace sys_scan { class WorldWritableScanner : public Scanner { public: std::string name() const override { return "world_writable"; } std::string description() const override { return "Find world-writable files in sensitive dirs"; } void scan(ScanContext& context) override; }; }
