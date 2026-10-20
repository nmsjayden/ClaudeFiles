//
//  kernel_research.h
//  ClaudeFiles
//
//  Kernel research toolkit for SPTM bypass investigation.
//  All functions are READ-ONLY unless explicitly marked as a write operation.
//

#ifndef kernel_research_h
#define kernel_research_h

#include <stdint.h>

/// Dump our process's kernel state: proc, proc_ro, ucred, sandbox.
/// Returns a malloc'd string (caller must free).
char *kresearch_dump_self(void);

/// Dump a target process's state by PID.
/// Returns a malloc'd string (caller must free).
char *kresearch_dump_proc(int pid);

/// Compare our process credentials to a target process (e.g., PID 1 = launchd).
/// Shows what's different between our ucred/sandbox and theirs.
/// Returns a malloc'd string (caller must free).
char *kresearch_compare_creds(int target_pid);

/// Check which sandbox operations are permitted for our process.
/// Tests: file-read-data, file-write-data, process-exec, process-fork,
///        process-exec*, mach-lookup, iokit-open, etc.
/// Returns a malloc'd string (caller must free).
char *kresearch_check_sandbox_ops(void);

/// Dump the full sandbox_label structure for our process, including the
/// platform_profile pointer and extension set.
/// Returns a malloc'd string (caller must free).
char *kresearch_dump_sandbox_profile(void);

/// [WRITE] Attempt to swap our sandbox profile pointer with launchd's.
/// This is an experimental operation — the sandbox_label is in writable memory.
/// Returns a malloc'd string describing what happened (caller must free).
char *kresearch_swap_sandbox_profile(void);

/// [WRITE] Attempt to add sandbox extensions for process-exec and process-fork.
/// Uses the same technique as the filesystem sandbox escape.
/// Returns a malloc'd string describing what happened (caller must free).
char *kresearch_add_exec_extension(void);

/// Test posix_spawn after research modifications and report detailed results.
/// Returns a malloc'd string (caller must free).
char *kresearch_test_spawn(void);

/// Read the persistent breadcrumb log from the last research run.
/// Breadcrumbs survive crashes — call this after relaunching to see
/// exactly where the previous run died.
/// Returns a malloc'd string (caller must free).
char *kresearch_read_breadcrumbs(void);

// ────────────────────────────────────────────────────────────────────
// Kernel research primitives — designed as Claude API tool backends.
// Each returns a malloc'd string with formatted results.
// ────────────────────────────────────────────────────────────────────

/// Read N bytes from a kernel virtual address and return a hex dump.
/// Returns a malloc'd string (caller must free).
char *kresearch_kread(uint64_t address, int size);

/// Read a single 64-bit value from a kernel address.
/// Returns a malloc'd string with the value in hex and decimal.
char *kresearch_kread64(uint64_t address);

/// Follow a chain of kernel pointers: read ptr at base+offsets[0],
/// then at result+offsets[1], etc. Returns all intermediate values.
/// offsets is a comma-separated string of hex/decimal offsets.
/// Returns a malloc'd string (caller must free).
char *kresearch_follow_chain(uint64_t base, const char *offsets_csv);

/// Get detailed proc_info for a given PID (or 0 for self).
/// Returns a malloc'd string (caller must free).
char *kresearch_proc_info(int pid);

/// Check sandbox_check for a specific operation (e.g., "process-exec",
/// "mach-lookup") with an optional target name.
/// Returns a malloc'd string (caller must free).
char *kresearch_sandbox_check_op(const char *operation, const char *name);

/// Dump N bytes of the sandbox structure at a given offset for our process.
/// Returns a malloc'd string with hex dump.
char *kresearch_sandbox_dump(int offset, int size);

/// Look up a symbol address via dlsym in a given framework path.
/// Returns a malloc'd string with the address.
char *kresearch_dlsym_lookup(const char *framework_path, const char *symbol_name);

/// Call a looked-up function pointer with up to 4 uint64 arguments.
/// Takes the framework path, function name, and up to 4 args.
/// Returns a malloc'd string with the return value.
char *kresearch_dlcall(const char *framework_path, const char *function_name,
                       uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);

/// Run a named research function by key (e.g., "dump_self", "swap_profile").
/// Wrapper so Claude can call any existing research function by name.
/// Returns a malloc'd string (caller must free).
char *kresearch_run_command(const char *command_name);

/// Walk the kernel process list and return info about all (or filtered) processes.
/// If name_filter is NULL or empty, returns all. Otherwise filters by name substring.
/// Returns a malloc'd string (caller must free).
char *kresearch_proc_list(const char *name_filter);

#endif /* kernel_research_h */
