#pragma once

#include "core/Config.h"
#include <string>

namespace sys_scan {

class GPGSigner {
public:
    GPGSigner() = default;
    ~GPGSigner() = default;

    // Sign output file with GPG
    bool sign_file(const Config& cfg);

private:
    bool validate_gpg_key(const std::string& key) const;
    std::string canonicalize_path(const std::string& path) const;
};

} // namespace sys_scan