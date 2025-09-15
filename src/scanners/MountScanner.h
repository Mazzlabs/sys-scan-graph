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

    // Test helper function to check mount options
    static bool has_mount_option(const std::string& opts, const std::string& key) {
        // crude contains match on comma boundaries
        if(opts==key) return true;
        size_t pos = 0; std::string needle = key;
        while(true){
            pos = opts.find(key, pos);
            if(pos == std::string::npos) return false;
            bool left_ok = (pos==0) || opts[pos-1]==',';
            bool right_ok = (pos + key.size() == opts.size()) || opts[pos+key.size()]==',';
            if(left_ok && right_ok) return true;
            pos += key.size();
        }
    }
};

}
