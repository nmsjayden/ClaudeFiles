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

// ────────────────────────────────────────────────────────────────────
// Kernel WRITE primitives + advanced test tools
// ────────────────────────────────────────────────────────────────────

/// [WRITE] Write a single 64-bit value to a kernel address.
/// Returns a malloc'd string confirming the write + readback.
char *kresearch_kwrite64(uint64_t address, uint64_t value);

/// [WRITE] Write arbitrary bytes (hex string) to a kernel address.
/// hex_data is a hex string like "00000000" or "ff ff ff ff".
/// Returns a malloc'd string confirming the write + readback.
char *kresearch_kwrite(uint64_t address, const char *hex_data);

/// Test posix_spawn with a specific binary and args string.
/// Returns detailed error reporting including errno and sandbox deny info.
char *kresearch_posix_spawn_test(const char *binary_path, const char *args_str);

/// Attempt to consume a sandbox extension token string.
/// Returns a malloc'd string with the result (handle or error).
char *kresearch_sandbox_ext_consume(const char *token);

// ────────────────────────────────────────────────────────────────────
// Extension set analysis + process-exec bypass
// ────────────────────────────────────────────────────────────────────

/// [READ-ONLY] Dump all 16 extension set buckets with full details:
/// class names, extension paths, flags, linked list structure.
/// Includes raw hex dumps and checks BOTH our struct offsets AND lara's
/// offsets (OFF_EXT_DATA=0x40, OFF_EXT_DATALEN=0x48) for empirical
/// verification of the correct field layout.
/// Returns a malloc'd string (caller must free).
char *kresearch_dump_extensions(void);

/// [WRITE — SAFE] Attempt to add a process-exec sandbox extension
/// using the same kwrite path that the filesystem sandbox escape uses.
/// Only writes to extension_set memory (writable kernel heap).
/// Returns a malloc'd string describing what happened.
char *kresearch_patch_exec(void);

#endif /* kernel_research_h */
