#import "permission_utils.h"
#import "../kexploit/vnode.h"
#import "../kexploit/krw.h"
#import "../kexploit/offsets.h"
#import "../kexploit/xpaci.h"
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <libgen.h>

static void log_perm(const char *fmt, ...) {
    NSString *logPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"FilzaPermDebug.log"];
    FILE *f = fopen([logPath fileSystemRepresentation], "a");
    if (!f) return;
    
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    fprintf(f, "[%s] ", ts);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

bool is_ssv_protected_path(const char *path) {
    if (!path) return false;
    
    // SSV-protected paths: /System, /bin, /sbin, /usr/libexec
    if (strncmp(path, "/System", 7) == 0) return true;
    if (strncmp(path, "/bin", 4) == 0) return true;
    if (strncmp(path, "/sbin", 5) == 0) return true;
    if (strncmp(path, "/usr/libexec", 12) == 0) return true;
    
    return false;
}

bool get_parent_dir_info(const char *path, uid_t *uid, gid_t *gid, mode_t *mode) {
    if (!path || !uid || !gid || !mode) return false;
    
    char *pathCopy = strdup(path);
    char *parentDir = dirname(pathCopy);
    
    log_perm("get_parent_dir_info: path=%s parent=%s", path, parentDir);
    
    // Try user-level stat first
    struct stat st;
    if (stat(parentDir, &st) == 0) {
        *uid = st.st_uid;
        *gid = st.st_gid;
        *mode = st.st_mode;
        log_perm("User stat succeeded: uid=%d gid=%d mode=%o", *uid, *gid, *mode);
        free(pathCopy);
        return true;
    }
    
    log_perm("User stat failed, trying kernel-level read for %s", parentDir);
    
    // Fallback: kernel-level vnode read
    uint64_t vnode = get_vnode_for_path_by_chdir(parentDir);
    if (vnode == -1) {
        log_perm("Cannot get vnode for parent dir %s", parentDir);
        free(pathCopy);
        return false;
    }
    
    uint64_t v_data = kread64(vnode + off_vnode_v_data);
    if (!v_data) {
        log_perm("Cannot get v_data for parent dir %s", parentDir);
        free(pathCopy);
        return false;
    }
    
    *uid = kread32(v_data + 0x80);
    *gid = kread32(v_data + 0x84);
    *mode = kread16(v_data + 0x88);
    
    log_perm("Kernel read succeeded: uid=%d gid=%d mode=%o", *uid, *gid, *mode);
    free(pathCopy);
    return true;
}

static int apply_permissions_kernel(const char *path, uid_t uid, gid_t gid, mode_t mode) {
    log_perm("apply_permissions_kernel: %s uid=%d gid=%d mode=%o", path, uid, gid, mode);
    
    uint64_t vnode = get_vnode_for_path_by_open(path);
    if (vnode == -1) {
        log_perm("Cannot get vnode for %s", path);
        return -1;
    }
    
    uint64_t v_data = kread64(vnode + off_vnode_v_data);
    if (!v_data) {
        log_perm("Cannot get v_data for %s", path);
        return -1;
    }
    
    kwrite32(v_data + 0x80, uid);   // uid
    kwrite32(v_data + 0x84, gid);   // gid
    kwrite16(v_data + 0x88, mode & 0777);  // mode
    
    // Refresh vnode counters to trigger kernel revalidation
    uint32_t usec = kread32(vnode + off_vnode_v_usecount);
    uint32_t ioc = kread32(vnode + off_vnode_v_iocount);
    kwrite32(vnode + off_vnode_v_usecount, usec + 1);
    kwrite32(vnode + off_vnode_v_iocount, ioc + 1);
    kwrite32(vnode + off_vnode_v_usecount, usec);
    kwrite32(vnode + off_vnode_v_iocount, ioc);
    
    log_perm("Kernel permissions applied successfully");
    return 0;
}

int apply_parent_permissions(const char *path) {
    if (!path) return -1;
    
    log_perm("apply_parent_permissions: %s", path);
    
    uid_t uid;
    gid_t gid;
    mode_t mode;
    
    if (!get_parent_dir_info(path, &uid, &gid, &mode)) {
        log_perm("Failed to get parent dir info for %s", path);
        return -1;
    }
    
    // Try user-level chown first
    if (chown(path, uid, gid) == 0) {
        chmod(path, mode & 0777);
        log_perm("User-level chown/chmod succeeded");
        return 0;
    }
    
    log_perm("User-level chown failed, using kernel: %s", strerror(errno));
    
    // Fallback to kernel-level
    return apply_permissions_kernel(path, uid, gid, mode);
}

bool force_chown_root_wheel(const char *path) {
    if (!path) return false;
    
    log_perm("force_chown_root_wheel: %s", path);
    
    // For SSV paths, always use kernel-level
    return apply_permissions_kernel(path, 0, 0, 0644) == 0;
}

void apply_permissions_after_operation(const char *path, const char *operation) {
    if (!path || !operation) return;
    
    log_perm("apply_permissions_after_operation: %s (%s)", path, operation);
    
    if (is_ssv_protected_path(path)) {
        log_perm("SSV-protected path detected, forcing root:wheel");
        force_chown_root_wheel(path);
    } else {
        log_perm("Non-SSV path, applying parent permissions");
        apply_parent_permissions(path);
    }
}
