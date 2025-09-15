#pragma once
#include <string>
#include <mutex>
#include <iostream>

namespace sys_scan {

enum class LogLevel { Error=0, Warn=1, Info=2, Debug=3, Trace=4 };

class Logger {
public:
    static Logger& instance() { static Logger inst; return inst; }
    void set_level(LogLevel lvl) { level_ = lvl; }
    LogLevel level() const { return level_; }

    void log(LogLevel lvl, const std::string& msg) {
        if(static_cast<int>(lvl) <= static_cast<int>(level_)) {
            std::lock_guard<std::mutex> lock(mu_);
            std::ostream& os = (lvl==LogLevel::Error)? std::cerr : std::clog;
            os << prefix(lvl) << msg << std::endl;
        }
    }
    void error(const std::string& m){ log(LogLevel::Error,m);}    
    void warn(const std::string& m){ log(LogLevel::Warn,m);}    
    void info(const std::string& m){ log(LogLevel::Info,m);}    
    void debug(const std::string& m){ log(LogLevel::Debug,m);}  
    void trace(const std::string& m){ log(LogLevel::Trace,m);}  
private:
    LogLevel level_ = LogLevel::Info;
    std::mutex mu_;
    std::string prefix(LogLevel lvl) {
        switch(lvl){
            case LogLevel::Error: return "[ERROR] ";
            case LogLevel::Warn: return "[WARN ] ";
            case LogLevel::Info: return "[INFO ] ";
            case LogLevel::Debug: return "[DEBUG] ";
            case LogLevel::Trace: return "[TRACE] ";
        }
        return "";
    }
};

}
