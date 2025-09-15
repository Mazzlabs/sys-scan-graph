// Linux privilege & sandbox helpers (best-effort; compile-time gated)
#pragma once
namespace sys_scan {
void drop_capabilities(bool keep_cap_dac);
bool apply_seccomp_profile();
}
