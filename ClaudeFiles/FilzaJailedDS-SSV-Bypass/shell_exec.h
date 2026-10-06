#ifndef SHELL_EXEC_H
#define SHELL_EXEC_H

#include <stdio.h>

/// Execute a shell command and return stdout+stderr as a malloc'd string.
/// Caller must free() the returned pointer. Returns NULL on failure.
/// exit_code is set to the process exit code.
char *shell_exec(const char *command, int *exit_code);

#endif
