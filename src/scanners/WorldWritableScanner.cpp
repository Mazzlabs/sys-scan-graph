#include "WorldWritableScanner.h"
#include "../core/Report.h"
#include "../core/ScanContext.h"
#include "../core/Utils.h"
#include "../core/Config.h"
#include <sys/stat.h>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#ifdef __linux__
#include <sys/types.h>
#include <sys/xattr.h>
#endif

namespace sys_scan {

// Ultra-lean constants
static const size_t MAX_FILES_LEAN = 5000;
static const size_t MAX_PATH_LEN_LEAN = 256;
static const size_t MAX_INODES_LEAN = 1000;
static const size_t MAX_PATHS_PER_INODE = 3;

// Ultra-fast single-pass file batch structure
struct FileBatch {
    char paths[MAX_FILES_LEAN][MAX_PATH_LEN_LEAN];
    struct stat stats[MAX_FILES_LEAN];
    char shebangs[MAX_FILES_LEAN][128];
    bool has_suid[MAX_FILES_LEAN];
    bool has_caps[MAX_FILES_LEAN];
    bool is_world_writable[MAX_FILES_LEAN];
    size_t count;
};

// Ultra-fast inode tracking for hardlink detection
struct InodeEntry {
    ino_t inode;
    char paths[MAX_PATHS_PER_INODE][MAX_PATH_LEN_LEAN];
    size_t path_count;
};

// Ultra-fast batch file processor
static void process_file_batch_lean(FileBatch* batch, ScanContext& context,
                                   const std::vector<std::string>& exclude_patterns,
                                   int ww_limit, size_t* ww_count,
                                   const char* interpreters[], size_t interpreter_count,
                                   InodeEntry* inode_entries, size_t* inode_count) {

    for (size_t i = 0; i < batch->count; ++i) {
        const char* filepath = batch->paths[i];

        // Skip excluded files
        bool excluded = false;
        for (const auto& pat : exclude_patterns) {
            if (strstr(filepath, pat.c_str()) != nullptr) {
                excluded = true;
                break;
            }
        }
        if (excluded) continue;

        // World-writable check
        if (batch->is_world_writable[i] && (*ww_count < static_cast<size_t>(ww_limit) || ww_limit <= 0)) {
            Finding f;
            f.id = filepath;
            f.title = "World-writable file";
            f.severity = Severity::Medium;
            f.description = "File is world writable";

            // Adjust severity based on path
            if (strstr(filepath, "/tmp/") != nullptr) {
                f.severity = Severity::Low;
            } else if (strstr(filepath, ".so") != nullptr ||
                      strstr(filepath, "/bin/") != nullptr) {
                f.severity = Severity::High;
            }

            context.report.add_finding("world_writable", std::move(f));
            ++(*ww_count);
        }

        // SUID interpreter check
        if (batch->has_suid[i]) {
            const char* filename = strrchr(filepath, '/');
            filename = filename ? filename + 1 : filepath;

            bool is_interpreter = false;

            // Check filename first
            for (size_t j = 0; j < interpreter_count; ++j) {
                if (strcmp(filename, interpreters[j]) == 0) {
                    is_interpreter = true;
                    break;
                }
            }

            // Check shebang if needed
            if (!is_interpreter && batch->shebangs[i][0] == '#') {
                for (size_t j = 0; j < interpreter_count; ++j) {
                    if (strstr(batch->shebangs[i], interpreters[j]) != nullptr) {
                        is_interpreter = true;
                        break;
                    }
                }
            }

            if (is_interpreter) {
                Finding f;
                f.id = filepath;
                f.title = "Setuid interpreter";
                f.severity = Severity::Critical;
                f.description = "Setuid shell or script interpreter";
                f.metadata["rule"] = "setuid_interpreter";
                context.report.add_finding("world_writable", std::move(f));
            }
        }

        // File capabilities check
        if (batch->has_caps[i] && !(batch->stats[i].st_mode & S_ISUID)) {
            Finding f;
            f.id = filepath;
            f.title = "File capabilities binary";
            f.severity = Severity::Medium;
            f.description = "Binary has file capabilities set";
            f.metadata["rule"] = "file_capability";
            context.report.add_finding("world_writable", std::move(f));
        }

        // Track inodes for hardlink detection
        if (batch->has_suid[i] && *inode_count < MAX_INODES_LEAN) {
            ino_t inode = batch->stats[i].st_ino;

            // Find existing inode entry
            size_t entry_idx = SIZE_MAX;
            for (size_t j = 0; j < *inode_count; ++j) {
                if (inode_entries[j].inode == inode) {
                    entry_idx = j;
                    break;
                }
            }

            // Create new entry if needed
            if (entry_idx == SIZE_MAX) {
                entry_idx = *inode_count;
                inode_entries[entry_idx].inode = inode;
                inode_entries[entry_idx].path_count = 0;
                ++(*inode_count);
            }

            // Add path if space available
            if (entry_idx < *inode_count && inode_entries[entry_idx].path_count < MAX_PATHS_PER_INODE) {
                size_t path_idx = inode_entries[entry_idx].path_count;
                strncpy(inode_entries[entry_idx].paths[path_idx], filepath, MAX_PATH_LEN_LEAN - 1);
                inode_entries[entry_idx].paths[path_idx][MAX_PATH_LEN_LEAN - 1] = '\0';
                ++inode_entries[entry_idx].path_count;
            }
        }
    }
}

// Ultra-fast single-pass directory scanner
static size_t scan_directory_batch_lean(const char* dir_path, FileBatch* batch,
                                       size_t max_files, size_t start_idx) {
    DIR* dir = opendir(dir_path);
    if (!dir) return 0;

    size_t count = 0;

    while (count < max_files) {
        struct dirent* entry = readdir(dir);
        if (!entry) break;

        if (entry->d_name[0] == '.') continue;  // Skip hidden files

        // Build full path
        size_t dir_len = strlen(dir_path);
        size_t name_len = strlen(entry->d_name);

        if (dir_len + 1 + name_len >= MAX_PATH_LEN_LEAN) continue;  // Would overflow buffer

        char* filepath = batch->paths[start_idx + count];
        memcpy(filepath, dir_path, dir_len);
        filepath[dir_len] = '/';
        memcpy(filepath + dir_len + 1, entry->d_name, name_len + 1);

        // Single stat call for all checks
        struct stat* st = &batch->stats[start_idx + count];
        if (lstat(filepath, st) != 0) continue;

        // Only process regular files
        if (!S_ISREG(st->st_mode)) continue;

        // Batch all checks
        batch->has_suid[start_idx + count] = (st->st_mode & S_ISUID) != 0;
        batch->is_world_writable[start_idx + count] = (st->st_mode & S_IWOTH) != 0;

        // File capabilities check
        batch->has_caps[start_idx + count] = false;
#ifdef __linux__
        ssize_t cap_len = getxattr(filepath, "security.capability", nullptr, 0);
        batch->has_caps[start_idx + count] = (cap_len > 0);
#endif

        // Shebang check for SUID files only
        batch->shebangs[start_idx + count][0] = '\0';
        if (batch->has_suid[start_idx + count]) {
            int fd = open(filepath, O_RDONLY | O_CLOEXEC);
            if (fd != -1) {
                ssize_t bytes_read = read(fd, batch->shebangs[start_idx + count], 127);
                close(fd);

                if (bytes_read > 0) {
                    batch->shebangs[start_idx + count][bytes_read] = '\0';

                    // Null terminate at newline
                    char* newline = strchr(batch->shebangs[start_idx + count], '\n');
                    if (newline) *newline = '\0';
                }
            }
        }

        ++count;
    }

    closedir(dir);
    return count;
}

void WorldWritableScanner::scan(ScanContext& context) {
    // Interpreter list
    const char* interpreters[] = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby"};
    const size_t interpreter_count = sizeof(interpreters) / sizeof(interpreters[0]);

    // Directories to scan
    const char* scan_dirs[] = {"/usr/bin", "/bin", "/usr/local/bin", "/etc", "/var"};
    const size_t scan_dir_count = sizeof(scan_dirs) / sizeof(scan_dirs[0]);

    // Single batch for all files
    FileBatch* batch = new FileBatch();
    InodeEntry inode_entries[MAX_INODES_LEAN] = {};
    size_t inode_count = 0;
    size_t total_files = 0;
    size_t ww_count = 0;
    int ww_limit = context.config.fs_world_writable_limit;

    // Single-pass directory scanning
    for (size_t d = 0; d < scan_dir_count && total_files < MAX_FILES_LEAN; ++d) {
        size_t files_added = scan_directory_batch_lean(scan_dirs[d], batch, MAX_FILES_LEAN - total_files, total_files);
        total_files += files_added;
    }

    batch->count = total_files;

    // Process all files in single batch
    process_file_batch_lean(batch, context, context.config.world_writable_exclude,
                           ww_limit, &ww_count, interpreters, interpreter_count,
                           inode_entries, &inode_count);

    // Additional directories from config
    for (const auto& extra_dir : context.config.world_writable_dirs) {
        if (total_files >= MAX_FILES_LEAN) break;

        FileBatch* extra_batch = new FileBatch();
        size_t extra_files = scan_directory_batch_lean(extra_dir.c_str(), extra_batch,
                                                      MAX_FILES_LEAN - total_files, 0);
        extra_batch->count = extra_files;

        if (extra_files > 0) {
            process_file_batch_lean(extra_batch, context, context.config.world_writable_exclude,
                                   ww_limit, &ww_count, interpreters, interpreter_count,
                                   inode_entries, &inode_count);
            total_files += extra_files;
        }
        delete extra_batch;
    }

    delete batch;

    if (!context.config.fs_hygiene) return;  // Advanced checks gated

    // PATH directory world-writable detection (ultra-fast)
    const char* path_env = getenv("PATH");
    if (path_env) {
        const char* path_ptr = path_env;
        char path_seg[MAX_PATH_LEN_LEAN];

        while (*path_ptr) {
            // Extract path segment
            const char* colon = strchr(path_ptr, ':');
            size_t seg_len = colon ? (size_t)(colon - path_ptr) : strlen(path_ptr);

            if (seg_len > 0 && seg_len < sizeof(path_seg)) {
                memcpy(path_seg, path_ptr, seg_len);
                path_seg[seg_len] = '\0';

                struct stat st;
                if (stat(path_seg, &st) == 0 && S_ISDIR(st.st_mode)) {
                    if (st.st_mode & S_IWOTH) {
                        Finding f;
                        f.id = path_seg;
                        f.title = "World-writable PATH directory";
                        f.severity = Severity::High;
                        f.description = "Executable search path directory is world-writable";
                        f.metadata["rule"] = "path_dir_world_writable";
                        context.report.add_finding(this->name(), std::move(f));
                    }
                }
            }

            if (!colon) break;
            path_ptr = colon + 1;
        }
    }

    // Dangling SUID hardlinks detection (ultra-fast)
    const char* suspect_roots[] = {"/tmp", "/var/tmp", "/dev/shm"};
    const size_t suspect_count = sizeof(suspect_roots) / sizeof(suspect_roots[0]);

    for (size_t i = 0; i < inode_count; ++i) {
        const auto& entry = inode_entries[i];
        if (entry.path_count < 2) continue;

        bool has_system = false;
        bool has_suspect = false;

        for (size_t j = 0; j < entry.path_count; ++j) {
            const char* path = entry.paths[j];

            if (strncmp(path, "/usr/bin/", 10) == 0 ||
                strncmp(path, "/bin/", 5) == 0 ||
                strncmp(path, "/usr/sbin/", 11) == 0) {
                has_system = true;
            }

            for (size_t k = 0; k < suspect_count; ++k) {
                if (strncmp(path, suspect_roots[k], strlen(suspect_roots[k])) == 0) {
                    has_suspect = true;
                    break;
                }
            }
        }

        if (has_system && has_suspect) {
            Finding f;
            f.id = std::string(entry.paths[0]) + ":dangling_suid_link";
            f.title = "Dangling SUID hardlink";
            f.severity = Severity::High;
            f.description = "SUID binary hardlinked into temporary/untrusted location";
            f.metadata["rule"] = "dangling_suid_hardlink";

            std::string all_paths;
            for (size_t j = 0; j < entry.path_count; ++j) {
                if (j > 0) all_paths += ",";
                all_paths += entry.paths[j];
            }
            f.metadata["paths"] = all_paths;

            context.report.add_finding(this->name(), std::move(f));
        }
    }
}

}
