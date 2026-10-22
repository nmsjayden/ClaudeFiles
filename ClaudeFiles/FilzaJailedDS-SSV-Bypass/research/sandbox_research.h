//  sandbox_research.h
//  Private kernel sandbox structures for iOS 16–18 (arm64).
//
//  These layouts are derived from:
//    • Apple XNU open-source (mac_policy, kauth) for the outer wrapper
//    • Reverse-engineering of the Sandbox.kext binary (opa334 / 34306 research)
//    • Field names/order confirmed by every offsetof() + kwrite call in sandbox.m
//    • Cross-referenced with lara (rooootdev) which uses 16 buckets and
//      different extension offsets (OFF_EXT_DATA=0x40, OFF_EXT_DATALEN=0x48).
//      Our struct works on our device; dump_extensions verifies empirically.
//
//  Only the fields actually referenced in sandbox.m are declared; padding/unknown
//  words fill the rest to keep sizeof() correct for kreadbuf/kwritebuf.

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// ---------------------------------------------------------------------------
// Storage-class constants written to extension.file.storage_class
// ---------------------------------------------------------------------------
#define SC_NONE     0x0  // not yet issued
#define SC_ISSUED   0x1  // issued, active
#define SC_CONSUMED 0x2  // already consumed (one-shot extensions)

// ---------------------------------------------------------------------------
// struct sandbox_label
//   Kernel object pointed to by the MAC label slot for the Sandbox policy.
//   sandbox.m accesses only the `extension_set` pointer field.
// ---------------------------------------------------------------------------
struct sandbox_label {
    uint64_t              platform_profile;  // 0x00  (profile/policy pointer)
    uint64_t              unk1;              // 0x08  (unknown, often 0)
    struct extension_set *extension_set;     // 0x10  ← confirmed by sandbox_escape.m
    uint64_t              unk3;              // 0x18
};

// ---------------------------------------------------------------------------
// struct extension_set
//   Hash table of extension_class_node* buckets, indexed by extension type.
//   sandbox.m walks type_buckets[0..8]; lara uses 16 buckets on iOS 17–18.
//   We use 16 to ensure we don't miss any extension type buckets.
// ---------------------------------------------------------------------------
#define SANDBOX_EXT_NUM_BUCKETS 16
struct extension_set {
    struct extension_class_node *type_buckets[SANDBOX_EXT_NUM_BUCKETS]; // 0x00..0x7F
};

// ---------------------------------------------------------------------------
// struct extension_class_node
//   Linked-list node for one extension class (e.g. "com.apple.app-sandbox.read-write").
//   Must be exactly 0x20 bytes — confirmed by the kwrite_zone_element(..., 0x20) call.
//
//   CONFIRMED on iOS 18.1 (iPhone 14, A15 T8110) via device testing:
//   LARA's offsets are correct; our old layout (class_name=0x00) was WRONG.
// ---------------------------------------------------------------------------
struct extension_class_node {
    struct extension_class_node  *next;           // 0x00  sibling in bucket chain
    struct extension             *ext_list_head;  // 0x08  head of extension list
    const char                   *class_name;     // 0x10  pointer to class name string
    uint64_t                      count;          // 0x18
};  // sizeof == 0x20  ✓

// Convenience defines matching the struct above (for raw-byte access)
#define CN_OFF_NEXT       0x00
#define CN_OFF_EXT        0x08
#define CN_OFF_CLASSNAME  0x10
#define CN_OFF_COUNT      0x18

// ---------------------------------------------------------------------------
// Extension struct — field offsets confirmed via LARA and device testing.
//
// The full extension struct is ~0x60 bytes.  Only data_ptr and data_len are
// confirmed; the rest is filled with padding so sizeof() is correct for
// raw kreadbuf calls.  The sandbox escape uses raw-offset defines below
// rather than offsetof() so we don't depend on getting every field right.
// ---------------------------------------------------------------------------
#define EXT_OFF_DATA      0x40   // pointer to path/data string
#define EXT_OFF_DATALEN   0x48   // uint64 path length
#define EXT_RAW_SIZE      0x60   // how many bytes to raw-dump per extension

struct extension {
    uint8_t raw[EXT_RAW_SIZE];   // opaque — use EXT_OFF_* for field access
};
