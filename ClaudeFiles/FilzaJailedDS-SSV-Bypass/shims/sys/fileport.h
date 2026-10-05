// Shim for <sys/fileport.h> — available in iOS 18.5+ SDK (Xcode 16.4+)
// but the underlying Mach calls exist on all iOS 16+ kernels.
#pragma once

#include <mach/port.h>

#ifndef _SYS_FILEPORT_H_
#define _SYS_FILEPORT_H_

typedef mach_port_t fileport_t;

// These are Mach traps, declared here for SDKs that don't ship the header.
int fileport_makeport(int fd, fileport_t *port);
int fileport_makefd(fileport_t port);

#endif /* _SYS_FILEPORT_H_ */
