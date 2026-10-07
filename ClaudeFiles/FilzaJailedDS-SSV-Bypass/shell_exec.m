#include "shell_exec.h"
#include <stdlib.h>
#include <string.h>

/// shell_exec is no longer used — bash_exec is now implemented
/// natively in Swift (FileToolsExecutor.bashExec) using POSIX/Foundation
/// APIs instead of spawning processes, which iOS blocks.
///
/// This stub remains so existing code that links against it still compiles.
char *shell_exec(const char *command, int *exit_code) {
    if (exit_code) *exit_code = 127;
    const char *msg = "Error: shell exec unavailable on iOS. Use the built-in command handler.";
    return strdup(msg);
}
