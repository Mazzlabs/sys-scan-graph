#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace sys_scan {

class CompressionUtils {
public:
    static std::string decompress_xz_bounded(const std::string& path);
    static std::string decompress_gz_bounded(const std::string& path);
    static bool is_compressed(const std::string& path);
};

class ElfModuleHeuristics {
public:
    struct SectionInfo {
        std::string name;
        uint64_t flags = 0;
        uint64_t size = 0;
    };

    static std::vector<SectionInfo> parse_sections(const std::string& file_path);
    static bool has_wx_section(const std::vector<SectionInfo>& sections);
    static bool has_large_text_section(const std::vector<SectionInfo>& sections);
    static bool has_suspicious_section_name(const std::vector<SectionInfo>& sections);
};

class SignatureAnalyzer {
public:
    static bool is_unsigned_module(const std::string& file_path);
    static std::string compute_sha256(const std::string& file_path);
};

} // namespace sys_scan