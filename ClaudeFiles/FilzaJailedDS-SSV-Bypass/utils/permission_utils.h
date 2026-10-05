#ifndef permission_utils_h
#define permission_utils_h

#import <Foundation/Foundation.h>
#import <stdbool.h>
#import <sys/stat.h>
#import <unistd.h>

// Apply parent directory permissions to a file/directory
int apply_parent_permissions(const char *path);

// Force chown root:wheel on a path (kernel-level)
bool force_chown_root_wheel(const char *path);

// Check if a path is SSV-protected
bool is_ssv_protected_path(const char *path);

// Get parent directory info (uid, gid, mode)
bool get_parent_dir_info(const char *path, uid_t *uid, gid_t *gid, mode_t *mode);

// Kernel-level permission application for any operation (create/modify/delete)
void apply_permissions_after_operation(const char *path, const char *operation);

#endif
