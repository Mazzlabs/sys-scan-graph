#include "JSONWriter.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <map>
#include <unistd.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <fstream>
#include "Config.h"
#include "Severity.h"
#include <ctime>
#include <vector>
#include "JsonUtil.h"
#include "BuildInfo.h"
#include <iostream>

namespace sys_scan {
namespace {
    struct HostMeta {
        std::string hostname;
        std::string kernel;
        std::string arch;
        std::string os_pretty;
        std::string os_id;
        std::string os_version;
        std::string user;
        int uid=0,euid=0,gid=0,egid=0;
        std::string cmdline;
    };

    struct CanonVal {
        enum Type { T_OBJ, T_ARR, T_STR, T_NUM } type = T_OBJ;
        std::map<std::string, CanonVal> obj;
        std::vector<CanonVal> arr;
        std::string str; // for string & number token text
        CanonVal() = default;
        explicit CanonVal(Type t): type(t) {}
    };

    // Forward decls
    static void canon_emit(const CanonVal& v, std::ostream& os);

    using jsonutil::escape; using jsonutil::time_to_iso;

    static void collect_uname_info(HostMeta& h) {
        struct utsname u{};
        if (uname(&u) == 0) {
            h.kernel = u.release;
            h.arch = u.machine;
            h.hostname = u.nodename;
        }
    }

    static void parse_os_release_file(HostMeta& h) {
        std::ifstream f("/etc/os-release");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("PRETTY_NAME=", 0) == 0) {
                std::string v = line.substr(12);
                if (v.size() && v.front() == '"' && v.back() == '"') {
                    v = v.substr(1, v.size() - 2);
                }
                h.os_pretty = v;
            } else if (line.rfind("ID=", 0) == 0) {
                std::string v = line.substr(3);
                if (v.size() && v.front() == '"' && v.back() == '"') {
                    v = v.substr(1, v.size() - 2);
                }
                h.os_id = v;
            } else if (line.rfind("VERSION_ID=", 0) == 0) {
                std::string v = line.substr(11);
                if (v.size() && v.front() == '"' && v.back() == '"') {
                    v = v.substr(1, v.size() - 2);
                }
                h.os_version = v;
            }
        }
    }

    static void collect_user_info(HostMeta& h) {
        h.uid = getuid();
        h.euid = geteuid();
        h.gid = getgid();
        h.egid = getegid();
        if (auto* pw = getpwuid(h.uid); pw) {
            h.user = pw->pw_name;
        }
    }

    static void collect_cmdline_info(HostMeta& h) {
        std::ifstream cf("/proc/self/cmdline", std::ios::binary);
        std::string raw((std::istreambuf_iterator<char>(cf)), {});
        for (char c : raw) {
            if (c == '\0') {
                h.cmdline.push_back(' ');
            } else {
                h.cmdline.push_back(c);
            }
        }
        if (!h.cmdline.empty() && h.cmdline.front() == ' ') {
            h.cmdline.erase(h.cmdline.begin());
        }
    }

    static HostMeta collect_host_meta() {
        HostMeta h;
        collect_uname_info(h);
        parse_os_release_file(h);
        collect_user_info(h);
        collect_cmdline_info(h);
        return h;
    }

    static void apply_meta_overrides(HostMeta& h){
        auto get = [](const char* k)->const char*{ const char* v=getenv(k); return (v && *v)? v: nullptr; };
        if(auto v=get("SYS_SCAN_META_HOSTNAME")) h.hostname=v;
        if(auto v=get("SYS_SCAN_META_KERNEL")) h.kernel=v;
        if(auto v=get("SYS_SCAN_META_ARCH")) h.arch=v;
        if(auto v=get("SYS_SCAN_META_OS_PRETTY")) h.os_pretty=v;
        if(auto v=get("SYS_SCAN_META_OS_ID")) h.os_id=v;
        if(auto v=get("SYS_SCAN_META_OS_VERSION")) h.os_version=v;
        if(auto v=get("SYS_SCAN_META_USER")) h.user=v;
        if(auto v=get("SYS_SCAN_META_CMDLINE")) h.cmdline=v;
        // numeric ids not overridden for now (could be added if needed)
    }

    static void emit_string(const CanonVal& v, std::ostream& os) {
        os << '"' << escape(v.str) << '"';
    }

    static void emit_number(const CanonVal& v, std::ostream& os) {
        os << v.str;
    }

    static void emit_array(const CanonVal& v, std::ostream& os) {
        os << '[';
        bool first = true;
        for (const auto& e : v.arr) {
            if (!first) os << ',';
            first = false;
            canon_emit(e, os);
        }
        os << ']';
    }

    static void emit_object(const CanonVal& v, std::ostream& os) {
        os << '{';
        bool first = true;
        for (const auto& kv : v.obj) {
            if (!first) os << ',';
            first = false;
            os << '"' << escape(kv.first) << '"' << ':';
            canon_emit(kv.second, os);
        }
        os << '}';
    }

    static void canon_emit(const CanonVal& v, std::ostream& os) {
        switch (v.type) {
            case CanonVal::T_STR:
                emit_string(v, os);
                break;
            case CanonVal::T_NUM:
                emit_number(v, os);
                break;
            case CanonVal::T_ARR:
                emit_array(v, os);
                break;
            case CanonVal::T_OBJ:
                emit_object(v, os);
                break;
        }
    }
    static CanonVal build_meta_object(const HostMeta& host, const Config& cfg) {
        CanonVal meta{CanonVal::T_OBJ};
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };

        put_str(meta, "$schema", "https://github.com/J-mazz/sys-scan/schema/v2.json");
        put_str(meta, "arch", host.arch);
        
        if (!cfg.no_cmdline_meta && !host.cmdline.empty()) {
            put_str(meta, "cmdline", host.cmdline);
        }
        
        if (!cfg.no_user_meta) {
            put_str(meta, "egid", std::to_string(host.egid));
            put_str(meta, "euid", std::to_string(host.euid));
            put_str(meta, "gid", std::to_string(host.gid));
            put_str(meta, "uid", std::to_string(host.uid));
            put_str(meta, "user", host.user);
        }
        
        if (!cfg.no_hostname_meta) {
            put_str(meta, "hostname", host.hostname);
        }
        
        put_str(meta, "json_schema_version", "2");
        put_str(meta, "kernel", host.kernel);
        put_str(meta, "os_id", host.os_id);
        
        if (!host.os_pretty.empty()) {
            put_str(meta, "os_pretty", host.os_pretty);
        }
        
        if (!host.os_version.empty()) {
            put_str(meta, "os_version", host.os_version);
        }
        
        put_str(meta, "tool_version", buildinfo::APP_VERSION);
        
        if (std::getenv("SYS_SCAN_CANON_TIME_ZERO")) {
            put_str(meta, "normalized_time", "true");
        }

        return meta;
    }

    static void apply_meta_suppression_flags(CanonVal& meta, const Config& cfg) {
        // Post-construction hardening (idempotent): enforce suppression flags
        if (cfg.no_user_meta) {
            meta.obj.erase("uid");
            meta.obj.erase("euid");
            meta.obj.erase("gid");
            meta.obj.erase("egid");
            meta.obj.erase("user");
        }
        if (cfg.no_cmdline_meta) {
            meta.obj.erase("cmdline");
        }
        if (cfg.no_hostname_meta) {
            meta.obj.erase("hostname");
        }
    }

    static CanonVal build_provenance_object() {
        auto env_or = [](const char* name, const char* defv) -> const char* {
            const char* v = std::getenv(name);
            return (v && *v) ? v : defv;
        };

        CanonVal prov{CanonVal::T_OBJ};
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };

        put_str(prov, "compiler_id", env_or("SYS_SCAN_PROV_COMPILER_ID", buildinfo::COMPILER_ID));
        put_str(prov, "compiler_version", env_or("SYS_SCAN_PROV_COMPILER_VERSION", buildinfo::COMPILER_VERSION));
        put_str(prov, "git_commit", env_or("SYS_SCAN_PROV_GIT_COMMIT", buildinfo::GIT_COMMIT));
        put_str(prov, "cxx_standard", env_or("SYS_SCAN_PROV_CXX_STANDARD", buildinfo::CXX_STANDARD));
        put_str(prov, "cxx_flags", env_or("SYS_SCAN_PROV_CXX_FLAGS", buildinfo::CXX_FLAGS));
        
        const char* slsa_rt = std::getenv("SYS_SCAN_SLSA_LEVEL_RUNTIME");
        std::string slsa = slsa_rt ? slsa_rt : env_or("SYS_SCAN_PROV_SLSA_LEVEL", buildinfo::SLSA_LEVEL);
        put_str(prov, "slsa_level", slsa);
        put_str(prov, "build_type", env_or("SYS_SCAN_PROV_BUILD_TYPE", buildinfo::BUILD_TYPE));

        return prov;
    }

    static CanonVal build_effective_config_object(const Config& cfg) {
        CanonVal ec{CanonVal::T_OBJ};
        
        auto put_bool = [&](const std::string& k, bool v) {
            ec.obj[k].type = CanonVal::T_STR;
            ec.obj[k].str = v ? "true" : "false";
        };
        
        auto put_num = [&](const std::string& k, long long v) {
            ec.obj[k].type = CanonVal::T_NUM;
            ec.obj[k].str = std::to_string(v);
        };
        
        auto put_str = [&](const std::string& k, const std::string& v) {
            if (!v.empty()) {
                ec.obj[k].type = CanonVal::T_STR;
                ec.obj[k].str = v;
            }
        };

        put_str("min_severity", cfg.min_severity);
        put_str("fail_on_severity", cfg.fail_on_severity);
        put_bool("canonical", cfg.canonical);
        put_bool("ndjson", cfg.ndjson);
        put_bool("sarif", cfg.sarif);
        put_bool("pretty", cfg.pretty);
        put_bool("compact", cfg.compact);
        put_bool("rules_enable", cfg.rules_enable);
        put_bool("integrity", cfg.integrity);
        put_bool("integrity_pkg_verify", cfg.integrity_pkg_verify);
        put_bool("integrity_pkg_rehash", cfg.integrity_pkg_rehash);
        put_num("integrity_pkg_rehash_limit", cfg.integrity_pkg_rehash_limit);
        put_bool("modules_hash", cfg.modules_hash);
        put_bool("modules_summary_only", cfg.modules_summary_only);
        put_bool("modules_anomalies_only", cfg.modules_anomalies_only);
        put_bool("fs_hygiene", cfg.fs_hygiene);
        put_num("fs_world_writable_limit", cfg.fs_world_writable_limit);
        put_bool("process_inventory", cfg.process_inventory);
        put_bool("ioc_exec_trace", cfg.ioc_exec_trace);
        put_num("ioc_exec_trace_seconds", cfg.ioc_exec_trace_seconds);
        put_bool("ioc_env_trust", cfg.ioc_env_trust);
        put_bool("parallel", cfg.parallel);
        put_num("parallel_max_threads", cfg.parallel_max_threads);
        put_bool("containers", cfg.containers);
        put_bool("hardening", cfg.hardening);
        put_bool("seccomp", cfg.seccomp);
        put_bool("seccomp_strict", cfg.seccomp_strict);
        put_bool("compliance", cfg.compliance);

        return ec;
    }

    static CanonVal build_timings_array(const Report& report, bool zero_time) {
        CanonVal timings{CanonVal::T_ARR};
        
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };
        
        auto put_num = [&](CanonVal& o, const std::string& k, long long v) {
            o.obj[k].type = CanonVal::T_NUM;
            o.obj[k].str = std::to_string(v);
        };

        for (const auto& r : report.results()) {
            long long elapsed_ms = 0;
            if (r.start_time.time_since_epoch().count() && r.end_time.time_since_epoch().count() && r.end_time >= r.start_time) {
                elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time - r.start_time).count();
            }
            
            CanonVal t{CanonVal::T_OBJ};
            put_str(t, "scanner", r.scanner_name);
            put_num(t, "elapsed_ms", elapsed_ms);
            timings.arr.push_back(std::move(t));
        }

        return timings;
    }

    static CanonVal build_summary_object(long long duration_ms, size_t finding_total_all, size_t emitted_total,
                                       const std::string& slowest_name, long long slowest_ms,
                                       std::chrono::system_clock::time_point earliest,
                                       std::chrono::system_clock::time_point latest,
                                       const std::map<std::string, size_t>& severity_counts_all,
                                       const std::map<std::string, size_t>& severity_counts_emitted,
                                       size_t scanners_with_findings, size_t scanner_count, bool zero_time) {
        CanonVal summary{CanonVal::T_OBJ};
        
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };
        
        auto put_num = [&](CanonVal& o, const std::string& k, long long v) {
            o.obj[k].type = CanonVal::T_NUM;
            o.obj[k].str = std::to_string(v);
        };

        put_num(summary, "duration_ms", duration_ms);
        
        // Calculate findings per second
        double fps = (duration_ms > 0) ? (emitted_total * 1000.0 / duration_ms) : 0.0;
        std::ostringstream tmp;
        tmp.setf(std::ios::fixed);
        tmp << std::setprecision(2) << fps;
        std::string s = tmp.str();
        if (s.size() > 1) {
            while (s.size() > 1 && s.back() == '0') s.pop_back();
            if (!s.empty() && s.back() == '.') s.push_back('0');
        }
        summary.obj["findings_per_second"].type = CanonVal::T_NUM;
        summary.obj["findings_per_second"].str = s;

        put_num(summary, "finding_count_total", finding_total_all);
        put_num(summary, "finding_count_emitted", emitted_total);
        put_str(summary, "finished_at", time_to_iso(latest));
        put_str(summary, "scanner_count", std::to_string(scanner_count));
        put_num(summary, "scanners_with_findings", scanners_with_findings);

        // Severity counts
        CanonVal sev_all{CanonVal::T_OBJ};
        for (const auto& kv : severity_counts_all) {
            put_num(sev_all, kv.first, kv.second);
        }
        summary.obj["severity_counts"] = std::move(sev_all);

        CanonVal sev_emit{CanonVal::T_OBJ};
        for (const auto& kv : severity_counts_emitted) {
            put_num(sev_emit, kv.first, kv.second);
        }
        summary.obj["severity_counts_emitted"] = std::move(sev_emit);

        // Slowest scanner
        CanonVal slow{CanonVal::T_OBJ};
        put_str(slow, "elapsed_ms", std::to_string(slowest_ms));
        put_str(slow, "name", slowest_name);
        summary.obj["slowest_scanner"] = std::move(slow);

        put_str(summary, "started_at", time_to_iso(earliest));

        return summary;
    }

    static CanonVal build_results_array(const Report& report, const Config& cfg, bool zero_time, size_t& emitted_total) {
        CanonVal res_arr{CanonVal::T_ARR};
        
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };
        
        auto put_num = [&](CanonVal& o, const std::string& k, long long v) {
            o.obj[k].type = CanonVal::T_NUM;
            o.obj[k].str = std::to_string(v);
        };

        for (const auto& r : report.results()) {
            CanonVal rs{CanonVal::T_OBJ};
            put_str(rs, "scanner", r.scanner_name);
            put_str(rs, "start_time", zero_time ? "" : time_to_iso(r.start_time));
            put_str(rs, "end_time", zero_time ? "" : time_to_iso(r.end_time));
            
            long long elapsed_ms = 0;
            if (!zero_time && r.start_time.time_since_epoch().count() && r.end_time.time_since_epoch().count() && r.end_time >= r.start_time) {
                elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time - r.start_time).count();
            }
            put_num(rs, "elapsed_ms", elapsed_ms);

            // Filter findings by severity
            std::vector<const Finding*> filtered;
            for (const auto& f : r.findings) {
                if (severity_rank(cfg.min_severity) <= severity_rank_enum(f.severity)) {
                    filtered.push_back(&f);
                }
            }
            put_num(rs, "finding_count", filtered.size());
            emitted_total += filtered.size();

            // Sort findings if canonical
            if (cfg.canonical) {
                std::sort(filtered.begin(), filtered.end(), [](const Finding* a, const Finding* b) {
                    return a->id < b->id;
                });
            }

            // Build findings array
            CanonVal findings_arr{CanonVal::T_ARR};
            for (const auto* fp : filtered) {
                const auto& f = *fp;
                CanonVal fv{CanonVal::T_OBJ};
                put_str(fv, "description", f.description);
                put_str(fv, "id", f.id);
                put_str(fv, "base_severity_score", std::to_string(f.base_severity_score));
                put_str(fv, "severity", severity_to_string(f.severity));
                put_str(fv, "title", f.title);

                // Metadata
                CanonVal meta_md{CanonVal::T_OBJ};
                std::vector<std::pair<std::string, std::string>> meta_sorted(f.metadata.begin(), f.metadata.end());
                std::sort(meta_sorted.begin(), meta_sorted.end(), [](auto& a, auto& b) {
                    return a.first < b.first;
                });
                for (const auto& kv : meta_sorted) {
                    put_str(meta_md, kv.first, kv.second);
                }
                fv.obj["metadata"] = std::move(meta_md);
                findings_arr.arr.push_back(std::move(fv));
            }
            
            rs.obj["findings"] = std::move(findings_arr);
            res_arr.arr.push_back(std::move(rs));
        }

        return res_arr;
    }

    static CanonVal build_warnings_array(const Report& report) {
        CanonVal warns{CanonVal::T_ARR};
        
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };

        for (const auto& w : report.warnings()) {
            CanonVal wv{CanonVal::T_OBJ};
            // w.second format: code[:detail]
            auto pos = w.second.find(':');
            std::string code = (pos == std::string::npos) ? w.second : w.second.substr(0, pos);
            std::string detail = (pos == std::string::npos) ? "" : w.second.substr(pos + 1);
            put_str(wv, "code", code);
            if (!detail.empty()) {
                put_str(wv, "detail", detail);
            }
            put_str(wv, "scanner", w.first);
            warns.arr.push_back(std::move(wv));
        }

        return warns;
    }

    static CanonVal build_partial_warnings_array(const Report& report) {
        CanonVal pwarns{CanonVal::T_ARR};
        
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };

        for (const auto& w : report.partial_warnings()) {
            CanonVal wv{CanonVal::T_OBJ};
            put_str(wv, "message", w.second);
            put_str(wv, "scanner", w.first);
            pwarns.arr.push_back(std::move(wv));
        }

        return pwarns;
    }

    static CanonVal build_errors_array(const Report& report) {
        CanonVal errs{CanonVal::T_ARR};
        
        auto put_str = [&](CanonVal& o, const std::string& k, const std::string& v) {
            o.obj[k].type = CanonVal::T_STR;
            o.obj[k].str = v;
        };

        for (const auto& e : report.errors()) {
            CanonVal ev{CanonVal::T_OBJ};
            put_str(ev, "message", e.second);
            put_str(ev, "scanner", e.first);
            errs.arr.push_back(std::move(ev));
        }

        return errs;
    }

    static CanonVal build_summary_extension(long long total_risk_all, long long emitted_risk) {
        CanonVal se{CanonVal::T_OBJ};
        
        auto put_num = [&](CanonVal& o, const std::string& k, long long v) {
            o.obj[k].type = CanonVal::T_NUM;
            o.obj[k].str = std::to_string(v);
        };

        put_num(se, "total_risk_score", total_risk_all);
        put_num(se, "emitted_risk_score", emitted_risk);

        return se;
    }

    static CanonVal build_compliance_summary(const Report& report) {
        if (report.compliance_summary().empty()) {
            return CanonVal{CanonVal::T_OBJ}; // Return empty object if no compliance data
        }

        CanonVal comp{CanonVal::T_OBJ};
        
        for (const auto& stdkv : report.compliance_summary()) {
            CanonVal stdobj{CanonVal::T_OBJ};
            for (const auto& mkv : stdkv.second) {
                // Try to detect numeric vs string (simple heuristic)
                bool numeric = true;
                for (char c : mkv.second) {
                    if ((c < '0' || c > '9') && c != '.' && c != '-') {
                        numeric = false;
                        break;
                    }
                }
                if (numeric) {
                    stdobj.obj[mkv.first].type = CanonVal::T_NUM;
                    stdobj.obj[mkv.first].str = mkv.second;
                } else {
                    stdobj.obj[mkv.first].type = CanonVal::T_STR;
                    stdobj.obj[mkv.first].str = mkv.second;
                }
            }
            comp.obj[stdkv.first] = std::move(stdobj);
        }

        return comp;
    }

static CanonVal build_canonical(const Report& report, long long total_risk_all, long long emitted_risk, size_t finding_total_all, size_t scanners_with_findings, long long duration_ms, const std::string& slowest_name, long long slowest_ms, std::chrono::system_clock::time_point earliest, std::chrono::system_clock::time_point latest, const std::map<std::string,size_t>& severity_counts_all, const std::map<std::string,size_t>& severity_counts_emitted, const HostMeta& host, const Config& cfg){ bool zero_time=!!std::getenv("SYS_SCAN_CANON_TIME_ZERO"); if(zero_time){ earliest={}; latest={}; duration_ms=0; } CanonVal root{CanonVal::T_OBJ}; auto put_str=[&](CanonVal& o,const std::string& k,const std::string& v){ o.obj[k].type=CanonVal::T_STR; o.obj[k].str=v; }; auto put_num=[&](CanonVal& o,const std::string& k,long long v){ o.obj[k].type=CanonVal::T_NUM; o.obj[k].str=std::to_string(v); }; CanonVal meta = build_meta_object(host, cfg); CanonVal prov = build_provenance_object(); meta.obj["provenance"] = std::move(prov); CanonVal ec = build_effective_config_object(cfg); meta.obj["effective_config"] = std::move(ec); if(cfg.timings){ CanonVal timings = build_timings_array(report, zero_time); meta.obj["timings"] = std::move(timings); } apply_meta_suppression_flags(meta, cfg); root.obj["meta"]=std::move(meta); size_t emitted_total = 0; CanonVal summary = build_summary_object(duration_ms, finding_total_all, emitted_total, slowest_name, slowest_ms, earliest, latest, severity_counts_all, severity_counts_emitted, scanners_with_findings, report.results().size(), zero_time); root.obj["summary"]=std::move(summary); CanonVal res_arr = build_results_array(report, cfg, zero_time, emitted_total); root.obj["results"]=std::move(res_arr); // patch in emitted totals
 put_num(root.obj["summary"],"finding_count_emitted", emitted_total); if(duration_ms>0){ double fps2 = emitted_total*1000.0/duration_ms; std::ostringstream tmp; tmp.setf(std::ios::fixed); tmp<<std::setprecision(2)<<fps2; std::string s=tmp.str(); while(s.size()>1 && s.back()=='0') s.pop_back(); if(!s.empty()&&s.back()=='.') s.push_back('0'); root.obj["summary"].obj["findings_per_second"].str=s; }
 CanonVal warns = build_warnings_array(report); root.obj["collection_warnings"]=std::move(warns); CanonVal pwarns = build_partial_warnings_array(report); if(!pwarns.arr.empty()) root.obj["partial_warnings"]=std::move(pwarns); CanonVal errs = build_errors_array(report); root.obj["scanner_errors"]=std::move(errs); CanonVal se = build_summary_extension(total_risk_all, emitted_risk); root.obj["summary_extension"]=std::move(se);
 CanonVal comp = build_compliance_summary(report); if(!comp.obj.empty()) root.obj["compliance_summary"]=std::move(comp);
 // After meta object population, enforce suppression flags
 // (Inserted by tool)
 // Post-construction hardening: ensure suppression flags are enforced
 // This is idempotent and guards against any future code paths that might
 // insert sensitive fields before flags are evaluated.
 apply_meta_suppression_flags(meta, cfg);
 return root; }
} // end anonymous namespace

// Move write implementation outside anonymous namespace to correctly match class scope
    static void calculate_summary_metrics(const std::vector<ScanResult>& results, const Config& cfg,
                                         size_t& finding_total_all, std::map<std::string, size_t>& severity_counts_all,
                                         std::map<std::string, size_t>& severity_counts_emitted,
                                         long long& total_risk_all, long long& emitted_risk,
                                         std::chrono::system_clock::time_point& earliest,
                                         std::chrono::system_clock::time_point& latest,
                                         size_t& scanners_with_findings, long long& slowest_ms,
                                         std::string& slowest_name) {
        for (const auto& r : results) {
            finding_total_all += r.findings.size();
            if (!r.findings.empty()) scanners_with_findings++;
            
            if (earliest.time_since_epoch().count() == 0 || 
                (r.start_time.time_since_epoch().count() && r.start_time < earliest)) {
                earliest = r.start_time;
            }
            
            if (r.end_time.time_since_epoch().count() && 
                (latest.time_since_epoch().count() == 0 || r.end_time > latest)) {
                latest = r.end_time;
            }
            
            auto elapsed = (r.end_time.time_since_epoch().count() && r.start_time.time_since_epoch().count()) ?
                          std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time - r.start_time).count() : 0;
            if (elapsed > slowest_ms) {
                slowest_ms = elapsed;
                slowest_name = r.scanner_name;
            }
            
            for (const auto& f : r.findings) {
                severity_counts_all[severity_to_string(f.severity)]++;
                if (!f.operational_error) {
                    total_risk_all += f.base_severity_score;
                    if (severity_rank(cfg.min_severity) <= severity_rank_enum(f.severity)) {
                        severity_counts_emitted[severity_to_string(f.severity)]++;
                        emitted_risk += f.base_severity_score;
                    }
                }
            }
        }
    }

    static std::string generate_sarif_output(const std::vector<ScanResult>& results, const Config& cfg) {
        std::ostringstream s;
        s << "{\"$schema\":\"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{";
        s << "\"tool\":{\"driver\":{\"name\":\"sys-scan\",\"informationUri\":\"https://github.com/J-mazz/sys-scan\"}},";
        s << "\"results\":[";
        
        bool first = true;
        int minRank = severity_rank(cfg.min_severity);
        
        for (const auto& r : results) {
            for (const auto& f : r.findings) {
                if (severity_rank_enum(f.severity) < minRank) continue;
                
                if (!first) s << ",";
                first = false;
                
                s << "{\"ruleId\":\"" << escape(f.id) << "\",\"level\":\"" << escape(severity_to_string(f.severity))
                  << "\",\"message\":{\"text\":\"" << escape(f.title) << " - " << escape(f.description)
                  << "\"},\"properties\":{\"baseSeverityScore\":" << f.base_severity_score;
                
                auto it = f.metadata.find("mitre_techniques");
                if (it != f.metadata.end()) {
                    s << ",\"mitreTechniqueIds\":[";
                    std::string v = it->second;
                    size_t pos = 0;
                    bool firstId = true;
                    while (pos < v.size()) {
                        size_t comma = v.find(',', pos);
                        std::string tok = v.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
                        if (!tok.empty()) {
                            if (!firstId) s << ",";
                            firstId = false;
                            s << "\"" << escape(tok) << "\"";
                        }
                        if (comma == std::string::npos) break;
                        pos = comma + 1;
                    }
                    s << "]";
                }
                s << "}}";
            }
        }
        
        s << "]}]}";
        return s.str();
    }

    static std::string generate_ndjson_output(const std::vector<ScanResult>& results, const Config& cfg,
                                             const HostMeta& host, long long duration_ms, size_t finding_total_all,
                                             size_t emitted_total, size_t scanners_with_findings,
                                             const std::string& slowest_name, long long slowest_ms,
                                             long long total_risk_all, long long emitted_risk) {
        std::ostringstream nd;
        
        // Meta line
        nd << '{' << "\"type\":\"meta\",\"tool_version\":\"" << escape(buildinfo::APP_VERSION)
           << "\",\"schema\":\"2\"";
        if (std::getenv("SYS_SCAN_CANON_TIME_ZERO")) nd << ",\"normalized_time\":\"true\"";
        if (!cfg.no_hostname_meta) nd << ",\"hostname\":\"" << escape(host.hostname) << "\"";
        if (!cfg.no_user_meta) {
            nd << ",\"uid\":" << host.uid << ",\"euid\":" << host.euid << ",\"gid\":" << host.gid
               << ",\"egid\":" << host.egid << ",\"user\":\"" << escape(host.user) << "\"";
        }
        if (!cfg.no_cmdline_meta && !host.cmdline.empty()) {
            nd << ",\"cmdline\":\"" << escape(host.cmdline) << "\"";
        }
        nd << '}';
        nd << "\n";
        
        // Summary line
        nd << '{' << "\"type\":\"summary\",\"duration_ms\":" << duration_ms
           << ",\"finding_count_total\":" << finding_total_all
           << ",\"finding_count_emitted\":" << emitted_total
           << ",\"scanner_count\":" << results.size()
           << ",\"scanners_with_findings\":" << scanners_with_findings;
        
        if (!slowest_name.empty()) {
            nd << ",\"slowest_scanner\":{\"name\":\"" << escape(slowest_name)
               << "\",\"elapsed_ms\":" << slowest_ms << "}";
        }
        nd << '}';
        nd << "\n";
        
        // Timings
        if (cfg.timings) {
            for (const auto& r : results) {
                long long elapsed_ms = 0;
                if (r.start_time.time_since_epoch().count() && r.end_time.time_since_epoch().count() && 
                    r.end_time >= r.start_time) {
                    elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time - r.start_time).count();
                }
                nd << '{' << "\"type\":\"timing\",\"scanner\":\"" << escape(r.scanner_name)
                   << "\",\"elapsed_ms\":" << elapsed_ms << '}';
                nd << "\n";
            }
        }
        
        // Summary extension
        nd << '{' << "\"type\":\"summary_extension\",\"total_risk_score\":" << total_risk_all
           << ",\"emitted_risk_score\":" << emitted_risk << '}';
        nd << "\n";
        
        // Findings
        int minRank = severity_rank(cfg.min_severity);
        for (const auto& r : results) {
            for (const auto& f : r.findings) {
                if (severity_rank_enum(f.severity) < minRank) continue;
                
                nd << '{' << "\"type\":\"finding\",\"scanner\":\"" << escape(r.scanner_name)
                   << "\",\"id\":\"" << escape(f.id) << "\",\"severity\":\"" << escape(severity_to_string(f.severity))
                   << "\",\"base_severity_score\":" << f.base_severity_score;
                
                if (f.operational_error) nd << ",\"operational_error\":true";
                
                auto it = f.metadata.find("mitre_techniques");
                if (it != f.metadata.end()) {
                    nd << ",\"mitre_techniques\":\"" << escape(it->second) << "\"";
                }
                nd << '}';
                nd << "\n";
            }
        }
        
        return nd.str();
    }

    static std::string pretty_print_json(const std::string& compact_json) {
        std::string out;
        out.reserve(compact_json.size() * 2);
        int depth = 0;
        bool in_string = false;
        bool esc = false;
        
        auto indent = [&](int d) {
            for (int i = 0; i < d; i++) out.append("  ");
        };
        
        for (size_t i = 0; i < compact_json.size(); ++i) {
            char c = compact_json[i];
            out.push_back(c);
            
            if (esc) {
                esc = false;
                continue;
            }
            if (c == '\\') {
                esc = true;
                continue;
            }
            if (c == '"') {
                in_string = !in_string;
                continue;
            }
            if (in_string) continue;
            
            switch (c) {
                case '{':
                case '[':
                    out.push_back('\n');
                    depth++;
                    indent(depth);
                    break;
                case '}':
                case ']':
                    out.push_back('\n');
                    depth--;
                    if (depth < 0) depth = 0;
                    indent(depth);
                    break;
                case ',':
                    out.push_back('\n');
                    indent(depth);
                    break;
                case ':':
                    out.push_back(' ');
                    break;
                default:
                    break;
            }
        }
        out.push_back('\n');
        return out;
    }

std::string JSONWriter::write(const Report& report, const Config& cfg) const {
    // Summary metrics
    const auto& results = report.results(); 
    size_t finding_total_all = 0; 
    std::map<std::string, size_t> severity_counts_all; 
    std::map<std::string, size_t> severity_counts_emitted; 
    long long total_risk_all = 0; 
    long long emitted_risk = 0; 
    std::chrono::system_clock::time_point earliest{}; 
    std::chrono::system_clock::time_point latest{}; 
    size_t scanners_with_findings = 0; 
    long long slowest_ms = 0; 
    std::string slowest_name;
    
    calculate_summary_metrics(results, cfg, finding_total_all, severity_counts_all, severity_counts_emitted,
                             total_risk_all, emitted_risk, earliest, latest, scanners_with_findings,
                             slowest_ms, slowest_name);
    
    long long duration_ms = 0; 
    if (earliest.time_since_epoch().count() && latest.time_since_epoch().count() && latest >= earliest) {
        duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(latest - earliest).count();
    }
    
    auto host = collect_host_meta(); 
    apply_meta_overrides(host); 
    
    size_t emitted_total = 0; 
    for (const auto& pair : severity_counts_emitted) {
        emitted_total += pair.second;
    }
    
    CanonVal root = build_canonical(report, total_risk_all, emitted_risk, finding_total_all, scanners_with_findings,
                                   duration_ms, slowest_name, slowest_ms, earliest, latest, severity_counts_all,
                                   severity_counts_emitted, host, cfg);
    
    if (cfg.sarif) {
        return generate_sarif_output(results, cfg);
    }
    
    if (cfg.ndjson) {
        return generate_ndjson_output(results, cfg, host, duration_ms, finding_total_all, emitted_total,
                                     scanners_with_findings, slowest_name, slowest_ms, total_risk_all, emitted_risk);
    }
    
    std::ostringstream os; 
    canon_emit(root, os); 
    std::string compact = os.str();
    
    if (cfg.pretty && !cfg.compact) {
        return pretty_print_json(compact);
    }
    
    return compact;
}

} // namespace sys_scan
