#pragma once
#include "../core/Scanner.h"
namespace sys_scan { class NetworkScanner : public Scanner { public: std::string name() const override { return "network"; } std::string description() const override { return "Enumerate listening TCP/UDP sockets"; }     void scan(ScanContext& context) override; }; }
