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

#endif /* kernel_research_h */
