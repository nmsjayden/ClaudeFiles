//  sandbox_research.h
//  Private kernel sandbox structures for iOS 16–17 (arm64).
//
//  These layouts are derived from:
//    • Apple XNU open-source (mac_policy, kauth) for the outer wrapper
//    • Reverse-engineering of the Sandbox.kext binary (opa334 / 34306 research)
//    • Field names/order confirmed by every offsetof() + kwrite call in sandbox.m
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
//   sandbox.m walks type_buckets[0..8] and writes type_buckets[0] and [i].
// ---------------------------------------------------------------------------
struct extension_set {
    struct extension_class_node *type_buckets[9]; // 0x00..0x47  ← iterated by sandbox.m
    uint64_t                     unk[5];           // 0x48..0x6F  padding
};

// ---------------------------------------------------------------------------
// struct extension_class_node
//   Linked-list node for one extension class (e.g. "com.apple.app-sandbox.read-write").
//   Must be exactly 0x20 bytes — confirmed by the kwrite_zone_element(..., 0x20) call.
// ---------------------------------------------------------------------------
struct extension_class_node {
    const char                   *class_name;     // 0x00  ← read & overwritten
    struct extension_class_node  *next;           // 0x08  (sibling in bucket chain)
    struct extension             *ext_list_head;  // 0x10  ← head of extension list
    uint64_t                      count;          // 0x18
};  // sizeof == 0x20  ✓

// ---------------------------------------------------------------------------
// struct extension
//   A single granted sandbox extension (filesystem path entry).
//   sandbox.m uses offsetof() on: data_ptr, path_len, file.{consumed,
//   storage_class, st_dev}, and st_ino.
// ---------------------------------------------------------------------------
struct extension {
    struct extension *next;       // 0x00  linked list
    uint64_t          hash;       // 0x08
    void             *ext_class;  // 0x10  pointer to extension class object
    void             *data_ptr;   // 0x18  ← pointer to path string
    uint64_t          path_len;   // 0x20  ← written via kwrite64
    struct {
        uint8_t  consumed;        // 0x28  ← written via kwrite8
        uint8_t  storage_class;   // 0x29  ← written via kwrite8 with SC_ISSUED
        uint16_t unk_flags;       // 0x2A
        uint32_t st_dev;          // 0x2C  ← written via kwrite32
    } file;                       // 0x28
    uint64_t st_ino;              // 0x30  ← written via kwrite64
    uint64_t unk[4];              // 0x38..0x57  padding
};
