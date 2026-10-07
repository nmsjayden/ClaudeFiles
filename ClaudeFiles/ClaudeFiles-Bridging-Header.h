//
//  ClaudeFiles-Bridging-Header.h
//  Exposes the FilzaJailedDS sandbox-escape C/ObjC API to Swift.
//

// Core sandbox escape (walks kernel proc_ro → ucred → cr_label → sandbox)
#import "FilzaJailedDS-SSV-Bypass/sandbox_escape.h"

// Kernel exploit (opa334 exploit for iOS 17–26)
#import "FilzaJailedDS-SSV-Bypass/kexploit/kexploit_opa334.h"

// Kernel read/write utilities (proc_self, etc.)
#import "FilzaJailedDS-SSV-Bypass/kexploit/kutils.h"

// Sandbox extension patching (enables SSV-protected area writes)
#import "FilzaJailedDS-SSV-Bypass/kexploit/sandbox.h"

// Global exploit state flags (set_exploit_done, set_patching_done)
#import "FilzaJailedDS-SSV-Bypass/exploit_globals.h"

// Shell command execution (bypasses Swift's iOS popen restriction)
#import "FilzaJailedDS-SSV-Bypass/shell_exec.h"

// RemoteCall — call functions in other processes via Mach task ports
#import "FilzaJailedDS-SSV-Bypass/kexploit/RemoteCall.h"

// Kernel research toolkit (SPTM bypass investigation)
#import "FilzaJailedDS-SSV-Bypass/kernel_research.h"

// SQLite3 — query any database on the device
#include <sqlite3.h>
