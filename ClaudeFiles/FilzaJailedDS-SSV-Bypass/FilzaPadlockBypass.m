//
//  FilzaPadlockBypass.m
//  FilzaJailedDS-SSV-Bypass
//
//  Bypasses Filza's UI padlock and permission checks
//  Allows editing/creating/deleting files in ALL locations including /System
//

#import "FilzaPadlockBypass.h"
#import "utils/permission_utils.h"
#import <substrate.h>

static void logPadlock(const char *fmt, ...) {
    NSString *logPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"FilzaPadlockDebug.log"];
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

#pragma mark - Helper Functions

BOOL filza_canEditPath(NSString *path) {
    logPadlock("filza_canEditPath: %@ - returning YES", path);
    return YES;  // Always allow editing
}

BOOL filza_canWritePath(NSString *path) {
    logPadlock("filza_canWritePath: %@ - returning YES", path);
    return YES;  // Always allow writing
}

BOOL filza_canDeletePath(NSString *path) {
    logPadlock("filza_canDeletePath: %@ - returning YES", path);
    return YES;  // Always allow deletion
}

BOOL filza_canCreatePath(NSString *path) {
    logPadlock("filza_canCreatePath: %@ - returning YES", path);
    return YES;  // Always allow creation
}

#pragma mark - NZFileBrowserController Hooks

%hook NZFileBrowserController

- (BOOL)canEditItemAtURL:(NSURL *)url {
    %log;
    NSString *path = [url path];
    logPadlock("NZFileBrowserController::canEditItemAtURL: %@ - BYPASSING", path);
    return YES;
}

- (BOOL)isLocked {
    %log;
    logPadlock("NZFileBrowserController::isLocked - BYPASSING (returning NO)");
    return NO;  // Hide the padlock
}

- (BOOL)readOnlyMode {
    %log;
    logPadlock("NZFileBrowserController::readOnlyMode - BYPASSING (returning NO)");
    return NO;  // Disable read-only mode
}

- (BOOL)canCreateFiles {
    %log;
    logPadlock("NZFileBrowserController::canCreateFiles - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDeleteItems {
    %log;
    logPadlock("NZFileBrowserController::canDeleteItems - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - NZDirectoryController Hooks

%hook NZDirectoryController

- (BOOL)canCreateFiles {
    %log;
    logPadlock("NZDirectoryController::canCreateFiles - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDeleteItems {
    %log;
    logPadlock("NZDirectoryController::canDeleteItems - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)isLocked {
    %log;
    logPadlock("NZDirectoryController::isLocked - BYPASSING (returning NO)");
    return NO;
}

%end

#pragma mark - NZFileItem Hooks

%hook NZFileItem

- (BOOL)isLocked {
    %log;
    logPadlock("NZFileItem::isLocked - BYPASSING (returning NO)");
    return NO;
}

- (BOOL)canWrite {
    %log;
    logPadlock("NZFileItem::canWrite - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDelete {
    %log;
    logPadlock("NZFileItem::canDelete - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canEdit {
    %log;
    logPadlock("NZFileItem::canEdit - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - NZFileManager Hooks (with permission application)

%hook NZFileManager

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    %log;
    logPadlock("NZFileManager::createFileAtPath: %@ - applying permissions after", path);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([path UTF8String], "create");
    }
    
    return result;
}

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    %log;
    logPadlock("NZFileManager::copyItemAtPath: %@ -> %@ - applying permissions after", src, dst);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([dst UTF8String], "copy");
    }
    
    return result;
}

- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    %log;
    logPadlock("NZFileManager::moveItemAtPath: %@ -> %@ - applying permissions after", src, dst);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([dst UTF8String], "move");
    }
    
    return result;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)err {
    %log;
    logPadlock("NZFileManager::removeItemAtPath: %@ - allowing deletion", path);
    
    // For SSV paths, we need to clear the immutable flag before deletion
    if (is_ssv_protected_path([path UTF8String])) {
        logPadlock("SSV path detected, attempting to clear immutable flag");
        uint64_t vnode = get_vnode_for_path_by_open([path UTF8String]);
        if (vnode != -1) {
            uint64_t v_data = kread64(vnode + off_vnode_v_data);
            if (v_data) {
                // Clear UF_IMMUTABLE flag (0x8000)
                uint32_t flags = kread32(v_data + 0x70);
                kwrite32(v_data + 0x70, flags & ~0x8000);
                logPadlock("Cleared immutable flag for %@", path);
            }
        }
    }
    
    return %orig;
}

- (BOOL)replaceItemAtPath:(NSString *)path withItemAtPath:(NSString *)withItem error:(NSError **)err {
    %log;
    logPadlock("NZFileManager::replaceItemAtPath: %@ - applying permissions after", path);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([path UTF8String], "replace");
    }
    
    return result;
}

%end

#pragma mark - NZTextEditor Hooks (file modifications)

%hook NZTextEditor

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    %log;
    logPadlock("NZTextEditor::writeToFile: %@ - applying permissions after", path);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([path UTF8String], "modify");
    }
    
    return result;
}

%end

#pragma mark - NZFileViewer Hooks

%hook NZFileViewer

- (BOOL)canEdit {
    %log;
    logPadlock("NZFileViewer::canEdit - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canSave {
    %log;
    logPadlock("NZFileViewer::canSave - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - Initialization

void initFilzaPadlockBypass(void) {
    logPadlock("initFilzaPadlockBypass called - hooks are active");
}
