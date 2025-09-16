#include "ModuleScanner.h"
#include "../core/Report.h"
#include "../core/ScanContext.h"
#include <fstream>
#include <sstream>
#include "../core/Config.h"
#include <sys/utsname.h>
#include <unordered_map>
#include <unordered_set>
#include <filesystem>
#include <cstring>
#include <cstdio>
#include <memory>
#include <cstdint>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "ModuleUtils.h"
#include "ModuleHelpers.h"
#ifdef SYS_SCAN_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace sys_scan {

// Static configuration for better performance
static const size_t MAX_MODULES = 10000;
static const size_t SAMPLE_LIMIT = 10;
static const size_t OOT_SAMPLE_LIMIT = 5;
static const size_t UNSIGNED_SAMPLE_LIMIT = 5;
static const size_t HIDDEN_SAMPLE_LIMIT = 5;
static const size_t MISSING_FILE_SAMPLE_LIMIT = 5;
static const size_t SYSFS_ONLY_SAMPLE_LIMIT = 5;
static const size_t WX_SECTION_SAMPLE_LIMIT = 5;
static const size_t LARGE_TEXT_SAMPLE_LIMIT = 5;
static const size_t SUSPICIOUS_SECTION_SAMPLE_LIMIT = 5;

// Pre-allocated buffers for file reading
static const size_t READ_BUFFER_SIZE = 8192;
static char read_buffer[READ_BUFFER_SIZE];

// Optimized file reading function using POSIX I/O
static bool read_file_posix(const char* path, std::string& content) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return false;

    content.clear();
    content.reserve(READ_BUFFER_SIZE); // Pre-allocate

    ssize_t bytes_read;
    while ((bytes_read = read(fd, read_buffer, READ_BUFFER_SIZE)) > 0) {
        content.append(read_buffer, bytes_read);
    }

    close(fd);
    return bytes_read >= 0;
}

// Optimized line-by-line file reading
static bool read_lines_posix(const char* path, std::vector<std::string>& lines) {
    std::string content;
    if (!read_file_posix(path, content)) return false;

    lines.clear();
    lines.reserve(1000); // Pre-allocate reasonable capacity

    size_t start = 0;
    size_t end = content.find('\n');
    while (end != std::string::npos) {
        if (end > start) {
            lines.emplace_back(content.substr(start, end - start));
        }
        start = end + 1;
        end = content.find('\n', start);
    }
    if (start < content.size()) {
        lines.emplace_back(content.substr(start));
    }

    return true;
}

// Fast string splitting for module lines
static bool parse_module_line(const std::string& line, std::string& name) {
    size_t space_pos = line.find(' ');
    if (space_pos == std::string::npos) return false;

    name.assign(line.data(), space_pos);
    return !name.empty();
}

// Fast path stripping function
static std::string strip_extension(std::string s) {
    static const char* extensions[] = {".ko", ".ko.xz", ".ko.gz"};
    for (const char* ext : extensions) {
        size_t ext_len = strlen(ext);
        if (s.size() >= ext_len && memcmp(s.data() + s.size() - ext_len, ext, ext_len) == 0) {
            s.resize(s.size() - ext_len);
            break;
        }
    }
    return s;
}

// Pre-allocated data structures
struct ModuleScanData {
    std::unordered_map<std::string, std::string> name_to_path;
    std::unordered_set<std::string> builtin_modules;
    std::unordered_set<std::string> sysfs_modules;
    std::unordered_set<std::string> proc_modules_set;

    // Pre-allocate vectors with reasonable capacities
    std::vector<std::string> sample;
    std::vector<std::string> oot_sample;
    std::vector<std::string> unsigned_sample;
    std::vector<std::string> compressed_unsigned_sample;
    std::vector<std::string> missing_file_sample;
    std::vector<std::string> hidden_sample;
    std::vector<std::string> sysfs_only_sample;
    std::vector<std::string> wx_section_sample;
    std::vector<std::string> large_text_section_sample;
    std::vector<std::string> suspicious_section_name_sample;

    ModuleScanData() {
        name_to_path.reserve(2000);
        builtin_modules.reserve(1000);
        sysfs_modules.reserve(1000);
        proc_modules_set.reserve(1000);

        sample.reserve(SAMPLE_LIMIT);
        oot_sample.reserve(OOT_SAMPLE_LIMIT);
        unsigned_sample.reserve(UNSIGNED_SAMPLE_LIMIT);
        compressed_unsigned_sample.reserve(UNSIGNED_SAMPLE_LIMIT);
        missing_file_sample.reserve(MISSING_FILE_SAMPLE_LIMIT);
        hidden_sample.reserve(HIDDEN_SAMPLE_LIMIT);
        sysfs_only_sample.reserve(SYSFS_ONLY_SAMPLE_LIMIT);
        wx_section_sample.reserve(WX_SECTION_SAMPLE_LIMIT);
        large_text_section_sample.reserve(LARGE_TEXT_SAMPLE_LIMIT);
        suspicious_section_name_sample.reserve(SUSPICIOUS_SECTION_SAMPLE_LIMIT);
    }
};

// Forward declarations for extracted functions
void setup_scan_paths(const std::string& kernel_release, std::string& modules_dep_path,
                     std::string& modules_builtin_path, std::string& lib_modules_base);
void build_module_path_map(const std::string& modules_dep_path, ModuleScanData& data);
void build_builtin_modules_set(const std::string& modules_builtin_path, ModuleScanData& data);
void collect_sysfs_modules(ModuleScanData& data);
bool read_proc_modules(std::vector<std::string>& proc_lines);
void handle_simple_mode(ScanContext& context, const std::vector<std::string>& proc_lines);
void process_modules_detailed(ScanContext& context, ModuleScanData& data,
                            const std::vector<std::string>& proc_lines,
                            const std::string& lib_modules_base);
void build_summary_finding(ScanContext& context, const std::string& scanner_name, const ModuleScanData& data,
                          size_t total, size_t likely_out_of_tree, size_t unsigned_count,
                          size_t compressed_count, size_t compressed_scanned, size_t compressed_unsigned,
                          size_t missing_file_count, size_t hidden_in_proc_only_count,
                          size_t sysfs_only_count, size_t wx_section_modules,
                          size_t large_text_section_modules, size_t suspicious_name_section_modules);
bool is_out_of_tree_module(const std::string& path);
void analyze_module_signature(const std::string& path, const std::string& full_path,
                            bool& unsigned_mod, bool& missing_file, ScanContext& context);
void detect_hidden_module(const std::string& name, const ModuleScanData& data, bool& hidden_proc_only);
void process_module_anomalies(ScanContext& context, const std::string& name, const std::string& path,
                            const std::string& full_path, bool oot, bool unsigned_mod,
                            bool missing_file, bool hidden_proc_only, ModuleScanData& data,
                            size_t& wx_section_modules, size_t& large_text_section_modules,
                            size_t& suspicious_name_section_modules);

void setup_scan_paths(const std::string& kernel_release, std::string& modules_dep_path,
                     std::string& modules_builtin_path, std::string& lib_modules_base) {
    modules_dep_path = "/lib/modules/" + kernel_release + "/modules.dep";
    modules_builtin_path = "/lib/modules/" + kernel_release + "/modules.builtin";
    lib_modules_base = "/lib/modules/" + kernel_release + "/";
}

void build_module_path_map(const std::string& modules_dep_path, ModuleScanData& data) {
    std::vector<std::string> dep_lines;
    if (read_lines_posix(modules_dep_path.c_str(), dep_lines)) {
        for (auto& line : dep_lines) {
            if (line.empty()) continue;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;

            std::string path = line.substr(0, colon);
            size_t slash = path.find_last_of('/');
            std::string fname = (slash == std::string::npos) ? path : path.substr(slash + 1);
            std::string base = strip_extension(std::move(fname));

            data.name_to_path[std::move(base)] = std::move(path);
        }
    }
}

void build_builtin_modules_set(const std::string& modules_builtin_path, ModuleScanData& data) {
    std::vector<std::string> builtin_lines;
    if (read_lines_posix(modules_builtin_path.c_str(), builtin_lines)) {
        for (auto& line : builtin_lines) {
            if (line.empty()) continue;
            size_t slash = line.find_last_of('/');
            std::string fname = (slash == std::string::npos) ? line : line.substr(slash + 1);
            std::string base = strip_extension(std::move(fname));
            data.builtin_modules.insert(std::move(base));
        }
    }
}

void collect_sysfs_modules(ModuleScanData& data) {
    DIR* dir = opendir("/sys/module");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                data.sysfs_modules.insert(entry->d_name);
            }
        }
        closedir(dir);
    }
}

bool read_proc_modules(std::vector<std::string>& proc_lines) {
    return read_lines_posix("/proc/modules", proc_lines);
}

void handle_simple_mode(ScanContext& context, const std::string& scanner_name, const std::vector<std::string>& proc_lines) {
    for (const auto& line : proc_lines) {
        std::string name;
        if (parse_module_line(line, name)) {
            Finding f;
            f.id = std::move(name);
            f.title = "Module " + f.id;
            f.severity = Severity::Info;
            f.description = "Loaded kernel module";
            context.report.add_finding(scanner_name, std::move(f));
        }
    }
}

bool is_out_of_tree_module(const std::string& path) {
    return path.find("/extra/") != std::string::npos ||
           path.find("/updates/") != std::string::npos ||
           path.find("dkms") != std::string::npos ||
           path.find("nvidia") != std::string::npos ||
           path.find("virtualbox") != std::string::npos ||
           path.find("vmware") != std::string::npos;
}

void analyze_module_signature(const std::string& path, const std::string& full_path,
                            bool& unsigned_mod, bool& missing_file, const std::string& scanner_name,
                            ScanContext& context) {
    unsigned_mod = false;
    missing_file = false;

    if (path.size() >= 3 && memcmp(path.data() + path.size() - 3, ".ko", 3) == 0) {
        // Uncompressed module
        unsigned_mod = SignatureAnalyzer::is_unsigned_module(full_path);
    } else if (CompressionUtils::is_compressed(path)) {
        std::string contents;
        if (path.size() >= 6 && memcmp(path.data() + path.size() - 6, ".ko.xz", 6) == 0) {
            contents = CompressionUtils::decompress_xz_bounded(full_path);
        } else {
            contents = CompressionUtils::decompress_gz_bounded(full_path);
        }

        if (contents.empty()) {
            context.report.add_warning(scanner_name, WarnCode::DecompressFail, path);
        } else {
            if (contents.find("Module signature appended") == std::string::npos) {
                unsigned_mod = true;
            }
        }
    }

    // File existence check using stat for better performance
    struct stat st;
    if (stat(full_path.c_str(), &st) != 0) {
        missing_file = true;
    }
}

void detect_hidden_module(const std::string& name, const ModuleScanData& data, bool& hidden_proc_only) {
    hidden_proc_only = (data.sysfs_modules.find(name) == data.sysfs_modules.end() &&
                       data.builtin_modules.find(name) == data.builtin_modules.end());
}

void process_module_anomalies(ScanContext& context, const std::string& scanner_name, const std::string& name, const std::string& path,
                            const std::string& full_path, bool oot, bool unsigned_mod,
                            bool missing_file, bool hidden_proc_only, ModuleScanData& data,
                            size_t& wx_section_modules, size_t& large_text_section_modules,
                            size_t& suspicious_name_section_modules) {
    if (!oot && !unsigned_mod && !missing_file && !hidden_proc_only) {
        return; // No anomalies to report
    }

    Finding f;
    f.id = name;
    f.title = "Module anomaly: " + name;
    f.severity = Severity::Medium;
    f.description = "Kernel module anomaly";

    if (unsigned_mod) {
        f.metadata["unsigned"] = "true";
        f.severity = Severity::High;
        f.description = "Unsigned kernel module detected";
    }
    if (oot) {
        f.metadata["out_of_tree"] = "true";
        if (f.severity < Severity::High) f.severity = Severity::High;
        f.description = "Out-of-tree kernel module";
    }
    if (missing_file) {
        f.metadata["missing_file"] = "true";
        f.severity = Severity::High;
        f.description = "Module file missing on disk";
    }
    if (hidden_proc_only) {
        f.metadata["hidden_sysfs"] = "true";
        f.severity = Severity::High;
        f.description = "Module present in /proc/modules but missing in /sys/module";
    }

    // ELF section heuristics (only if file exists)
    if (!full_path.empty() && !missing_file) {
        auto sections = ElfModuleHeuristics::parse_sections(full_path);
        if (!sections.empty()) {
            if (ElfModuleHeuristics::has_wx_section(sections)) {
                f.metadata["wx_section"] = "true";
                if (f.severity < Severity::High) f.severity = Severity::High;
                ++wx_section_modules;
                if (data.wx_section_sample.size() < WX_SECTION_SAMPLE_LIMIT) {
                    data.wx_section_sample.push_back(name);
                }
            }
            if (ElfModuleHeuristics::has_large_text_section(sections)) {
                uint64_t text_size = 0;
                for (const auto& s : sections) {
                    if (s.name == ".text") {
                        text_size = s.size;
                        break;
                    }
                }
                f.metadata["large_text_section"] = std::to_string(text_size);
                if (f.severity < Severity::High) f.severity = Severity::High;
                ++large_text_section_modules;
                if (data.large_text_section_sample.size() < LARGE_TEXT_SAMPLE_LIMIT) {
                    data.large_text_section_sample.push_back(name);
                }
            }
            if (ElfModuleHeuristics::has_suspicious_section_name(sections)) {
                for (const auto& s : sections) {
                    if (ElfModuleHeuristics::has_suspicious_section_name({s})) {
                        f.metadata["suspicious_section_name"] = s.name;
                        if (f.severity < Severity::High) f.severity = Severity::High;
                        ++suspicious_name_section_modules;
                        if (data.suspicious_section_name_sample.size() < SUSPICIOUS_SECTION_SAMPLE_LIMIT) {
                            data.suspicious_section_name_sample.push_back(name);
                        }
                        break;
                    }
                }
            }
        }
    }

#ifdef SYS_SCAN_HAVE_OPENSSL
    if (context.config.modules_hash && !full_path.empty() && !missing_file) {
        std::string hash = SignatureAnalyzer::compute_sha256(full_path);
        if (!hash.empty()) {
            f.metadata["sha256"] = hash;
        }
    }
#endif

    if (!path.empty()) f.metadata["path"] = path;
    context.report.add_finding(scanner_name, std::move(f));
}

void process_modules_detailed(ScanContext& context, const std::string& scanner_name, ModuleScanData& data,
                            const std::vector<std::string>& proc_lines,
                            const std::string& lib_modules_base) {
    size_t total = 0;
    size_t likely_out_of_tree = 0;
    size_t unsigned_count = 0;
    size_t compressed_count = 0;
    size_t compressed_scanned = 0;
    size_t compressed_unsigned = 0;
    size_t missing_file_count = 0;
    size_t hidden_in_proc_only_count = 0;
    size_t wx_section_modules = 0;
    size_t large_text_section_modules = 0;
    size_t suspicious_name_section_modules = 0;

    for (const auto& line : proc_lines) {
        std::string name;
        if (!parse_module_line(line, name)) continue;

        ++total;
        if (data.sample.size() < SAMPLE_LIMIT) {
            data.sample.push_back(name);
        }

        auto itp = data.name_to_path.find(name);
        std::string path = (itp == data.name_to_path.end()) ? std::string() : itp->second;

        // Check if out-of-tree
        bool oot = false;
        if (!path.empty() && is_out_of_tree_module(path)) {
            oot = true;
            ++likely_out_of_tree;
            if (data.oot_sample.size() < OOT_SAMPLE_LIMIT) {
                data.oot_sample.push_back(name);
            }
        }

        // Analyze module signature and file existence
        bool unsigned_mod = false;
        bool missing_file = false;
        std::string full_path;
        if (!path.empty()) {
            full_path = lib_modules_base + path;
            analyze_module_signature(path, full_path, unsigned_mod, missing_file, scanner_name, context);

            if (CompressionUtils::is_compressed(path)) {
                ++compressed_count;
                if (!unsigned_mod) {
                    ++compressed_scanned;
                } else {
                    ++compressed_unsigned;
                    if (data.compressed_unsigned_sample.size() < UNSIGNED_SAMPLE_LIMIT) {
                        data.compressed_unsigned_sample.push_back(name);
                    }
                }
            }
        }

        if (unsigned_mod) {
            ++unsigned_count;
            if (data.unsigned_sample.size() < UNSIGNED_SAMPLE_LIMIT) {
                data.unsigned_sample.push_back(name);
            }
        }

        if (missing_file) {
            ++missing_file_count;
            if (data.missing_file_sample.size() < MISSING_FILE_SAMPLE_LIMIT) {
                data.missing_file_sample.push_back(name);
            }
        }

        // Check for hidden modules
        bool hidden_proc_only = false;
        detect_hidden_module(name, data, hidden_proc_only);
        if (hidden_proc_only) {
            ++hidden_in_proc_only_count;
            if (data.hidden_sample.size() < HIDDEN_SAMPLE_LIMIT) {
                data.hidden_sample.push_back(name);
            }
        }

        // Process anomalies if in anomalies-only mode
        if (context.config.modules_anomalies_only) {
            process_module_anomalies(context, scanner_name, name, path, full_path, oot, unsigned_mod,
                                   missing_file, hidden_proc_only, data,
                                   wx_section_modules, large_text_section_modules,
                                   suspicious_name_section_modules);
        }
    }

    // Build proc modules set for sysfs-only detection
    for (const auto& line : proc_lines) {
        std::string name;
        if (parse_module_line(line, name)) {
            data.proc_modules_set.insert(std::move(name));
        }
    }

    // Find sysfs-only modules
    size_t sysfs_only_count = 0;
    for (const auto& m : data.sysfs_modules) {
        if (data.builtin_modules.find(m) == data.builtin_modules.end() &&
            data.proc_modules_set.find(m) == data.proc_modules_set.end()) {
            ++sysfs_only_count;
            if (data.sysfs_only_sample.size() < SYSFS_ONLY_SAMPLE_LIMIT) {
                data.sysfs_only_sample.push_back(m);
            }
        }
    }

    if (context.config.modules_anomalies_only) return; // Done with anomalies-only mode

    // Create summary finding
    build_summary_finding(context, scanner_name, data, total, likely_out_of_tree, unsigned_count,
                         compressed_count, compressed_scanned, compressed_unsigned,
                         missing_file_count, hidden_in_proc_only_count, sysfs_only_count,
                         wx_section_modules, large_text_section_modules, suspicious_name_section_modules);
}

void build_summary_finding(ScanContext& context, const std::string& scanner_name, const ModuleScanData& data,
                          size_t total, size_t likely_out_of_tree, size_t unsigned_count,
                          size_t compressed_count, size_t compressed_scanned, size_t compressed_unsigned,
                          size_t missing_file_count, size_t hidden_in_proc_only_count,
                          size_t sysfs_only_count, size_t wx_section_modules,
                          size_t large_text_section_modules, size_t suspicious_name_section_modules) {
    // Create summary finding
    Finding f;
    f.id = "module_summary";
    f.title = "Kernel modules summary";
    f.description = "Loaded kernel modules inventory";

    // Severity escalation based on findings
    Severity sev = Severity::Info;
    if (likely_out_of_tree > 0) sev = Severity::Medium;
    if (unsigned_count > 0 || hidden_in_proc_only_count > 0 ||
        missing_file_count > 0 || sysfs_only_count > 0) sev = Severity::High;
    f.severity = sev;

    // Add all metadata efficiently
    f.metadata["total"] = std::to_string(total);
    f.metadata["sample"] = [&]() {
        std::string s;
        for (size_t i = 0; i < data.sample.size(); ++i) {
            if (i) s += ",";
            s += data.sample[i];
        }
        return s;
    }();

    f.metadata["out_of_tree_count"] = std::to_string(likely_out_of_tree);
    if (!data.oot_sample.empty()) {
        std::string s;
        for (size_t i = 0; i < data.oot_sample.size(); ++i) {
            if (i) s += ",";
            s += data.oot_sample[i];
        }
        f.metadata["out_of_tree_sample"] = std::move(s);
    }

    f.metadata["unsigned_count"] = std::to_string(unsigned_count);
    if (compressed_count > 0) {
        f.metadata["compressed_count"] = std::to_string(compressed_count);
    }
    if (compressed_scanned > 0) {
        f.metadata["compressed_scanned"] = std::to_string(compressed_scanned);
    }
    if (compressed_unsigned > 0) {
        f.metadata["compressed_unsigned"] = std::to_string(compressed_unsigned);
    }

    if (!data.unsigned_sample.empty()) {
        std::string s;
        for (size_t i = 0; i < data.unsigned_sample.size(); ++i) {
            if (i) s += ",";
            s += data.unsigned_sample[i];
        }
        f.metadata["unsigned_sample"] = std::move(s);
    }

    if (!data.compressed_unsigned_sample.empty()) {
        std::string s;
        for (size_t i = 0; i < data.compressed_unsigned_sample.size(); ++i) {
            if (i) s += ",";
            s += data.compressed_unsigned_sample[i];
        }
        f.metadata["compressed_unsigned_sample"] = std::move(s);
    }

    if (missing_file_count > 0) {
        f.metadata["missing_file_count"] = std::to_string(missing_file_count);
        if (!data.missing_file_sample.empty()) {
            std::string s;
            for (size_t i = 0; i < data.missing_file_sample.size(); ++i) {
                if (i) s += ",";
                s += data.missing_file_sample[i];
            }
            f.metadata["missing_file_sample"] = std::move(s);
        }
    }

    if (hidden_in_proc_only_count > 0) {
        f.metadata["hidden_proc_only_count"] = std::to_string(hidden_in_proc_only_count);
        if (!data.hidden_sample.empty()) {
            std::string s;
            for (size_t i = 0; i < data.hidden_sample.size(); ++i) {
                if (i) s += ",";
                s += data.hidden_sample[i];
            }
            f.metadata["hidden_proc_only_sample"] = std::move(s);
        }
    }

    if (sysfs_only_count > 0) {
        f.metadata["sysfs_only_count"] = std::to_string(sysfs_only_count);
        if (!data.sysfs_only_sample.empty()) {
            std::string s;
            for (size_t i = 0; i < data.sysfs_only_sample.size(); ++i) {
                if (i) s += ",";
                s += data.sysfs_only_sample[i];
            }
            f.metadata["sysfs_only_sample"] = std::move(s);
        }
    }

    // Add taint flags info
    {
        std::string tainted_content;
        if (read_file_posix("/proc/sys/kernel/tainted", tainted_content)) {
            // Remove trailing whitespace
            while (!tainted_content.empty() && (tainted_content.back() == '\n' || tainted_content.back() == ' ')) {
                tainted_content.pop_back();
            }
            if (!tainted_content.empty()) {
                f.metadata["taint_value"] = tainted_content;
                // Decode bits
                unsigned long val = std::strtoul(tainted_content.c_str(), nullptr, 10);
                if (val) {
                    static const struct { unsigned long bit; const char* name; } bits[] = {
                        {0, "PROPRIETARY_MODULE"}, {1, "FORCED_MODULE"}, {2, "UNSAFE_SMP"},
                        {3, "FORCED_RMMOD"}, {4, "MACHINE_CHECK"}, {5, "BAD_PAGE"},
                        {6, "USER"}, {7, "DIE"}, {8, "OVERRIDDEN_ACPI_TABLE"},
                        {9, "WARN"}, {10, "OOPS"}, {11, "HARDWARE_INCOMPAT"},
                        {12, "SOFTWARE_INCOMPAT"}, {13, "FIRMWARE_WORKAROUND"},
                        {14, "CRAP"}, {15, "FIRMWARE_BUG"}, {16, "RANDSTRUCT"},
                        {17, "PANIC"}
                    };
                    std::string flags;
                    for (const auto& b : bits) {
                        if (val & (1UL << b.bit)) {
                            if (!flags.empty()) flags += ",";
                            flags += b.name;
                        }
                    }
                    if (!flags.empty()) f.metadata["taint_flags"] = std::move(flags);
                }
            }
        }
    }

    // /proc/kallsyms visibility
    {
        std::string kallsyms_content;
        if (read_file_posix("/proc/kallsyms", kallsyms_content)) {
            size_t lines = 0;
            size_t limited = 0;
            size_t start = 0;
            size_t end = kallsyms_content.find('\n');

            // Sample first 5000 lines for performance
            while (end != std::string::npos && lines < 5000) {
                ++lines;
                if (end > start) {
                    const char* line_start = kallsyms_content.data() + start;
                    size_t line_len = end - start;
                    if (line_len > 1 && line_start[0] == '0' && line_start[1] == '0') {
                        ++limited;
                    }
                }
                start = end + 1;
                end = kallsyms_content.find('\n', start);
            }

            f.metadata["kallsyms_readable"] = "yes";
            f.metadata["kallsyms_sampled"] = std::to_string(lines);
            if (lines < 100) f.metadata["kallsyms_low"] = "true";
            if (limited > 0 && limited == lines) f.metadata["kallsyms_all_zero"] = "true";
        } else {
            f.metadata["kallsyms_readable"] = "no";
        }
    }

    context.report.add_finding(scanner_name, std::move(f));
}

void ModuleScanner::scan(ScanContext& context) {
    ModuleScanData data;
    auto& cfg = context.config;

    // Get kernel release
    struct utsname un {};
    if (uname(&un) != 0) return;
    std::string kernel_release = un.release;

    // Build paths once
    std::string modules_dep_path, modules_builtin_path, lib_modules_base;
    setup_scan_paths(kernel_release, modules_dep_path, modules_builtin_path, lib_modules_base);

    if (!cfg.modules_summary_only && !cfg.modules_anomalies_only) {
        // Simple mode: just list modules
        std::vector<std::string> proc_lines;
        if (read_proc_modules(proc_lines)) {
            handle_simple_mode(context, this->name(), proc_lines);
        }
        return;
    }

    // Summary/anomalies mode: gather detailed stats

    // Build module name->path map from modules.dep
    build_module_path_map(modules_dep_path, data);

    // Prepare built-in module name set
    build_builtin_modules_set(modules_builtin_path, data);

    // Collect sysfs module directory names
    collect_sysfs_modules(data);

    // Read /proc/modules and process modules
    std::vector<std::string> proc_lines;
    if (!read_proc_modules(proc_lines)) return;

    process_modules_detailed(context, this->name(), data, proc_lines, lib_modules_base);
}

} // namespace sys_scan
