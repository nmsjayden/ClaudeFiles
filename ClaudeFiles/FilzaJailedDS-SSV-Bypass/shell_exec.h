#ifndef SHELL_EXEC_H
#define SHELL_EXEC_H

#include <stdio.h>

/// Elevate our process credentials to root + platform binary via kernel r/w.
/// Patches ucred (UID/GID → 0), cs_flags (CS_PLATFORM_BINARY), p_flag (TF_PLATFORM).
/// Returns 0 on success, -1 on failure. Only runs once per session.
int elevate_process_credentials(void);

/// Execute a shell command via posix_spawn and return stdout+stderr as a malloc'd string.
/// Caller must free() the returned pointer. Returns NULL on failure.
/// exit_code is set to the process exit code.
/// If posix_spawn fails with EPERM, automatically calls elevate_process_credentials() and retries.
char *shell_exec(const char *command, int *exit_code);

#endif
