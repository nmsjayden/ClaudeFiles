import Foundation
import UIKit

final class FileToolsExecutor {

    private let writeBlocklist = ["/System/Library/CoreServices", "/usr/lib", "/bin", "/sbin"]

    /// Serial queue to prevent concurrent access to non-thread-safe remote_call globals.
    private static let remoteCallQueue = DispatchQueue(label: "com.claudefiles.remotecall")

    func execute(name: String, input: [String: AnyJSON]) async -> String {
        let path      = input["path"]?.string      ?? ""
        let content   = input["content"]?.string   ?? ""
        let directory = input["directory"]?.string ?? ""
        let pattern   = input["pattern"]?.string   ?? ""

        let command   = input["command"]?.string   ?? ""

        switch name {
        case "read_file":      return readFile(path: path)
        case "write_file":     return writeFile(path: path, content: content)
        case "list_directory": return listDir(path: path)
        case "search_files":   return search(dir: directory, pattern: pattern)
        case "get_file_info":  return fileInfo(path: path)
        case "bash_exec":      return await bashExec(command: command)
        case "grep_search":    return grepSearch(pattern: pattern, directory: directory.isEmpty ? "/" : directory)
        case "head_file":      return headFile(path: path, lines: input["lines"]?.intValue ?? 50)
        case "tail_file":      return tailFile(path: path, lines: input["lines"]?.intValue ?? 50)
        case "process_list":   return processList()
        case "device_info":    return await deviceInfo()
        case "open_url":       return await openURL(input["url"]?.string ?? "")
        case "remote_call":    return await remoteCall(process: input["process"]?.string ?? "",
                                                       function: input["function"]?.string ?? "",
                                                       args: input["args"]?.arrayValue ?? [])
        case "sqlite_query":   return sqliteQuery(dbPath: input["database"]?.string ?? "",
                                                   query: input["query"]?.string ?? "")
        case "installed_apps": return installedApps()
        case "read_plist":     return readPlist(path: path)
        case "memory_dump":    return await memoryDump(process: input["process"]?.string ?? "",
                                                        address: input["address"]?.string ?? "0",
                                                        size: input["size"]?.intValue ?? 256)
        case "app_control":    return await appControl(action: input["action"]?.string ?? "",
                                                        target: input["target"]?.string ?? "")
        case "copy_move_file": return copyMoveFile(source: input["source"]?.string ?? "",
                                                     destination: input["destination"]?.string ?? "",
                                                     move: input["move"]?.string == "true")
        default:               return "Unknown tool: \(name)"
        }
    }

    private func readFile(path: String) -> String {
        guard !path.isEmpty else { return "Error: path required" }
        DebugLog.log("readFile: \(path)")
        do {
            let text = try String(contentsOfFile: path, encoding: .utf8)
            DebugLog.log("  → success, \(text.count) chars")
            return text.count > 20_000
                ? String(text.prefix(20_000)) + "\n[truncated — \(text.count) total chars]"
                : text
        } catch {
            let ns = error as NSError
            DebugLog.log("  → text failed: domain=\(ns.domain) code=\(ns.code) desc=\(ns.localizedDescription)")
            // Try FileManager binary
            if let data = FileManager.default.contents(atPath: path) {
                DebugLog.log("  → FileManager binary read ok, \(data.count) bytes")
                if let text = String(data: data, encoding: .utf8) {
                    return text.count > 20_000
                        ? String(text.prefix(20_000)) + "\n[truncated — \(text.count) total chars]"
                        : text
                }
                return "Binary (\(data.count) bytes). Hex: " +
                    data.prefix(128).map { String(format: "%02x", $0) }.joined(separator: " ")
            }
            // POSIX fallback
            if let data = posixRead(path: path) {
                DebugLog.log("  → POSIX read ok, \(data.count) bytes")
                if let text = String(data: data, encoding: .utf8) {
                    return text.count > 20_000
                        ? String(text.prefix(20_000)) + "\n[truncated — \(text.count) total chars]"
                        : text
                }
                return "Binary (\(data.count) bytes). Hex: " +
                    data.prefix(128).map { String(format: "%02x", $0) }.joined(separator: " ")
            }
            DebugLog.log("  → POSIX read failed, errno=\(errno) (\(String(cString: strerror(errno))))")
            return "Error reading \(path): \(describe(error, at: path))"
        }
    }

    private func posixRead(path: String) -> Data? {
        let fd = open(path, O_RDONLY)
        if fd < 0 { return nil }
        defer { close(fd) }
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = buf.withUnsafeMutableBufferPointer { ptr in
                read(fd, ptr.baseAddress, ptr.count)
            }
            if n < 0 { return nil }
            if n == 0 { break }
            data.append(buf, count: n)
            if data.count > 2_000_000 { break } // safety cap
        }
        return data
    }

    private func posixListDir(path: String) -> [String]? {
        guard let dir = opendir(path) else { return nil }
        defer { closedir(dir) }
        var names: [String] = []
        while let entry = readdir(dir) {
            let name = withUnsafePointer(to: entry.pointee.d_name) { ptr -> String in
                ptr.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            names.append(name)
        }
        return names
    }

    private func writeFile(path: String, content: String) -> String {
        guard !path.isEmpty else { return "Error: path required" }
        for blocked in writeBlocklist where path.hasPrefix(blocked) {
            return "Error: \(blocked) is blocked for safety"
        }
        let fm = FileManager.default
        if fm.fileExists(atPath: path) {
            try? fm.copyItem(atPath: path, toPath: path + ".claudebackup")
        }
        do {
            try content.write(toFile: path, atomically: true, encoding: .utf8)
            return "Wrote \(content.utf8.count) bytes to \(path)"
        } catch {
            return "Error writing: \(error.localizedDescription)"
        }
    }

    private func listDir(path: String) -> String {
        guard !path.isEmpty else { return "Error: path required" }
        DebugLog.log("listDir: \(path)")
        let fm = FileManager.default

        // Diagnostic: does the path exist? Is it a directory? What are its POSIX perms?
        var isDir: ObjCBool = false
        let exists = fm.fileExists(atPath: path, isDirectory: &isDir)
        DebugLog.log("  → exists=\(exists), isDir=\(isDir.boolValue)")
        if exists {
            if let attrs = try? fm.attributesOfItem(atPath: path) {
                let perm = (attrs[.posixPermissions] as? Int).map { String(format: "%o", $0) } ?? "?"
                let owner = attrs[.ownerAccountName] as? String ?? "?"
                let type = (attrs[.type] as? FileAttributeType)?.rawValue ?? "?"
                DebugLog.log("  → attrs: perm=\(perm) owner=\(owner) type=\(type)")
            }
            DebugLog.log("  → isReadable=\(fm.isReadableFile(atPath: path))")
        }

        var items: [String] = []
        do {
            items = try fm.contentsOfDirectory(atPath: path)
            DebugLog.log("  → FileManager success, \(items.count) items")
        } catch {
            let ns = error as NSError
            DebugLog.log("  → FileManager failed: domain=\(ns.domain) code=\(ns.code) desc=\(ns.localizedDescription)")

            // Fallback: try POSIX opendir — DarkSword may expose fs through this path differently
            if let posixItems = posixListDir(path: path) {
                DebugLog.log("  → POSIX opendir succeeded with \(posixItems.count) items")
                items = posixItems
            } else {
                DebugLog.log("  → POSIX opendir also failed, errno=\(errno) (\(String(cString: strerror(errno))))")
                return "Error listing \(path): \(describe(error, at: path))"
            }
        }
        return items.sorted().map { name -> String in
            var isDir: ObjCBool = false
            fm.fileExists(atPath: (path as NSString).appendingPathComponent(name), isDirectory: &isDir)
            return isDir.boolValue ? "\(name)/" : name
        }.joined(separator: "\n")
    }

    private func search(dir: String, pattern: String) -> String {
        guard !dir.isEmpty, !pattern.isEmpty else { return "Error: directory and pattern required" }
        guard let enumerator = FileManager.default.enumerator(atPath: dir) else {
            return "Cannot enumerate \(dir)"
        }
        var matches: [String] = []
        for case let name as String in enumerator {
            if name.localizedCaseInsensitiveContains(pattern) {
                matches.append((dir as NSString).appendingPathComponent(name))
            }
            if matches.count >= 200 { matches.append("... (limited to 200)"); break }
        }
        return matches.isEmpty ? "No matches for '\(pattern)' in \(dir)" : matches.joined(separator: "\n")
    }

    private func fileInfo(path: String) -> String {
        guard !path.isEmpty else { return "Error: path required" }
        let fm = FileManager.default
        let attrs: [FileAttributeKey: Any]
        do {
            attrs = try fm.attributesOfItem(atPath: path)
        } catch {
            return "Error getting info for \(path): \(describe(error, at: path))"
        }
        var lines: [String] = []
        if let size = attrs[.size]             as? Int  { lines.append("Size: \(size) bytes") }
        if let mod  = attrs[.modificationDate]          { lines.append("Modified: \(mod)") }
        if let perm = attrs[.posixPermissions] as? Int  { lines.append(String(format: "Permissions: %o", perm)) }
        if let owner = attrs[.ownerAccountName]         { lines.append("Owner: \(owner)") }
        if let type = attrs[.type] as? FileAttributeType { lines.append("Type: \(type.rawValue)") }
        return lines.joined(separator: "\n")
    }

    // MARK: - bash_exec (remote exec via mediaserverd — safe to crash/respawn)

    private func bashExec(command: String) async -> String {
        guard !command.isEmpty else { return "Error: command required" }

        // Block dangerous commands
        let blocked = ["rm -rf /", "mkfs", "dd if=", ":(){ :", "fork bomb",
                       "reboot", "shutdown", "halt"]
        for b in blocked where command.contains(b) {
            return "Error: blocked dangerous command"
        }

        // ── DIAGNOSTIC DUMP ──
        // NSLog flushes immediately to syslog — survives C-level crashes.
        // DebugLog writes to Documents/debug.log — survives app restarts but may not flush before a crash.
        let startTime = CFAbsoluteTimeGetCurrent()
        NSLog("╔══════════════════════════════════════════════════════════════")
        NSLog("║ [bashExec] START")
        NSLog("║ Command : %@", String(command.prefix(200)))
        NSLog("║ PID     : %d", ProcessInfo.processInfo.processIdentifier)
        NSLog("║ Thread  : %@", Thread.current.description)
        NSLog("╚══════════════════════════════════════════════════════════════")

        DebugLog.log("[bashExec] ═══ START cmd=\(command.prefix(200)) pid=\(ProcessInfo.processInfo.processIdentifier)")

        // ── SANDBOX STATE CHECK ──
        let sandboxStatus = await MainActor.run { SandboxManager.shared.status }
        let escaped = sandboxStatus.isUsable
        NSLog("[bashExec] Sandbox status: %@ (isUsable=%d, isEscaped=%d, isPartial=%d)",
              sandboxStatus.label, escaped ? 1 : 0,
              sandboxStatus.isEscaped ? 1 : 0,
              sandboxStatus.isPartial ? 1 : 0)
        DebugLog.log("[bashExec] Sandbox: \(sandboxStatus.label) usable=\(escaped)")

        guard escaped else {
            NSLog("[bashExec] ✘ ABORT: sandbox escape not active (status=%@)", sandboxStatus.label)
            return "Error: sandbox escape required for bash_exec. Run the exploit first. Current status: \(sandboxStatus.label)"
        }

        // ── PROCESS VISIBILITY CHECK ──
        // sysctl(KERN_PROC_ALL) from sandbox usually can't see system daemons.
        // This is informational — init_remote_call uses kernel r/w to find them.
        var visibleCount = 0
        var visibleDaemons: [String] = []
        let targetCandidates = ["mediaserverd", "backboardd", "SpringBoard", "launchd", "CommCenter"]
        for name in targetCandidates {
            if let pid = findPid(byName: name) {
                visibleDaemons.append("\(name)(\(pid))")
                visibleCount += 1
            }
        }
        NSLog("[bashExec] Process visibility: %d/%d daemons visible via sysctl: [%@]",
              visibleCount, targetCandidates.count, visibleDaemons.joined(separator: ", "))

        // Also count total visible processes
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        if sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0 {
            let totalProcs = size / MemoryLayout<kinfo_proc>.stride
            NSLog("[bashExec] Total processes visible via sysctl: %d", totalProcs)
        }

        let targetProcess: String
        if visibleDaemons.contains(where: { $0.hasPrefix("mediaserverd") }) {
            targetProcess = "mediaserverd"
        } else if visibleDaemons.contains(where: { $0.hasPrefix("backboardd") }) {
            targetProcess = "backboardd"
        } else {
            targetProcess = "mediaserverd"
            NSLog("[bashExec] ⚠ Target daemons not visible via sysctl (expected in sandbox). Will use kernel r/w to find mediaserverd.")
        }
        NSLog("[bashExec] Target process: %@", targetProcess)

        // ── KERNEL R/W QUICK TEST ──
        // Try a harmless kread to verify kernel r/w is still working before init_remote_call
        let selfProc = proc_self()
        NSLog("[bashExec] Kernel r/w check: proc_self() = 0x%llx", selfProc)
        DebugLog.log("[bashExec] proc_self=0x\(String(selfProc, radix: 16))")
        if selfProc == 0 {
            NSLog("[bashExec] ✘ proc_self() returned 0 — kernel r/w may be dead!")
            DebugLog.log("[bashExec] ✘ ABORT: proc_self=0, kernel r/w dead")
            return "Error: kernel read/write appears to be dead (proc_self returned NULL). The exploit may need to be re-run."
        }

        let tmpOut = "/tmp/.claude_cmd_\(ProcessInfo.processInfo.processIdentifier)"

        return await withCheckedContinuation { (cont: CheckedContinuation<String, Never>) in
            let once = OnceResume(cont)

            // Timeout — 30s to allow serial queue wait + execution
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 30) {
                let elapsed = CFAbsoluteTimeGetCurrent() - startTime
                NSLog("[bashExec] ✘ TIMEOUT after 30s (wall time: %.1fs)", elapsed)
                once.resume("Error: bash_exec timed out after 30s")
            }

            // Serialize all remote_call access — the C globals are NOT thread-safe
            FileToolsExecutor.remoteCallQueue.async { [self] in
                let queueWait = CFAbsoluteTimeGetCurrent() - startTime
                NSLog("[bashExec] ▶ Acquired serial queue (waited %.2fs)", queueWait)
                NSLog("[bashExec] ▶ Calling init_remote_call(\"%@\", useMigFilter=true)…", targetProcess)

                let t0 = CFAbsoluteTimeGetCurrent()
                let initRet = init_remote_call(targetProcess, true)
                let t1 = CFAbsoluteTimeGetCurrent()

                NSLog("[bashExec] ◀ init_remote_call(%@) returned %d in %.3fs", targetProcess, initRet, t1 - t0)
                DebugLog.log("[bashExec] init_remote_call(\(targetProcess))=\(initRet) in \(String(format: "%.3f", t1 - t0))s")

                guard initRet == 0 else {
                    // Try fallback only if primary was mediaserverd
                    if targetProcess == "mediaserverd" {
                        NSLog("[bashExec] ▶ Primary failed, trying backboardd…")
                        let t2 = CFAbsoluteTimeGetCurrent()
                        let initRet2 = init_remote_call("backboardd", true)
                        let t3 = CFAbsoluteTimeGetCurrent()
                        NSLog("[bashExec] ◀ init_remote_call(backboardd) returned %d in %.3fs", initRet2, t3 - t2)
                        DebugLog.log("[bashExec] init_remote_call(backboardd)=\(initRet2) in \(String(format: "%.3f", t3 - t2))s")

                        guard initRet2 == 0 else {
                            NSLog("[bashExec] ✘ Both daemons failed: mediaserverd=%d, backboardd=%d", initRet, initRet2)
                            once.resume("Error: could not attach to any system daemon (mediaserverd=\(initRet), backboardd=\(initRet2)). Is sandbox escape active?")
                            return
                        }
                        defer {
                            NSLog("[bashExec] ▶ destroy_remote_call (backboardd)…")
                            destroy_remote_call()
                            NSLog("[bashExec] ◀ destroy_remote_call done")
                        }

                        let trojanAddr = g_RC_trojanMem
                        NSLog("[bashExec] g_RC_trojanMem (backboardd) = 0x%llx", trojanAddr)
                        guard trojanAddr != 0 else {
                            NSLog("[bashExec] ✘ trojanMem is NULL after successful init!")
                            once.resume("Error: remote trojan memory not allocated (backboardd). init succeeded but shared memory is null.")
                            return
                        }

                        self.executeViaRemoteCall(command: command, tmpOut: tmpOut, once: once, startTime: startTime)
                        return
                    }
                    once.resume("Error: init_remote_call(\(targetProcess)) failed with code \(initRet). Is sandbox escape active?")
                    return
                }

                defer {
                    NSLog("[bashExec] ▶ destroy_remote_call (%@)…", targetProcess)
                    destroy_remote_call()
                    NSLog("[bashExec] ◀ destroy_remote_call done")
                }

                // Verify trojan memory was actually allocated before writing to it
                let trojanAddr = g_RC_trojanMem
                NSLog("[bashExec] g_RC_trojanMem = 0x%llx (page-aligned: %@)",
                      trojanAddr, (trojanAddr & 0xFFF) == 0 ? "YES" : "NO")
                DebugLog.log("[bashExec] trojanMem=0x\(String(trojanAddr, radix: 16))")

                guard trojanAddr != 0 else {
                    NSLog("[bashExec] ✘ trojanMem is NULL after successful init!")
                    once.resume("Error: remote trojan memory not allocated. init_remote_call succeeded but shared memory is null.")
                    return
                }

                NSLog("[bashExec] ✓ All checks passed, executing command…")
                self.executeViaRemoteCall(command: command, tmpOut: tmpOut, once: once, startTime: startTime)
            }
        }
    }

    /// Thread-safe "resume exactly once" wrapper for CheckedContinuation.
    private final class OnceResume {
        private let lock = NSLock()
        private var resumed = false
        private let cont: CheckedContinuation<String, Never>
        init(_ cont: CheckedContinuation<String, Never>) { self.cont = cont }
        func resume(_ value: String) {
            lock.lock()
            defer { lock.unlock() }
            guard !resumed else { return }
            resumed = true
            cont.resume(returning: value)
        }
    }

    /// Execute a command string via system() in the currently-attached remote process.
    /// Captures output by redirecting to a temp file, then reads it back.
    private func executeViaRemoteCall(command: String, tmpOut: String,
                                       once: OnceResume, startTime: CFAbsoluteTime) {
        // Build the shell command that redirects output to our temp file
        let wrappedCmd = "(\(command)) > \(tmpOut) 2>&1; echo $? >> \(tmpOut)"

        let trojanAddr = g_RC_trojanMem
        let cmdLen = wrappedCmd.utf8.count
        NSLog("[bashExec] ▶ remote_writeStr(0x%llx, %d bytes)…", trojanAddr, cmdLen)
        NSLog("[bashExec]   Wrapped command: %@", String(wrappedCmd.prefix(300)))

        // Safety: trojan memory page is 4096 bytes — don't overflow
        guard cmdLen < 4096 else {
            NSLog("[bashExec] ✘ Command too long for trojan page: %d bytes (max 4095)", cmdLen)
            once.resume("Error: command too long (\(cmdLen) bytes). Max is ~4095 bytes for remote execution.")
            return
        }

        // Write command string to trojan shared memory page
        guard remote_writeStr(trojanAddr, wrappedCmd) else {
            NSLog("[bashExec] ✘ remote_writeStr FAILED (trojan=0x%llx)", trojanAddr)
            DebugLog.log("[bashExec] ✘ remote_writeStr failed at 0x\(String(trojanAddr, radix: 16))")
            once.resume("Error: failed to write command to remote process memory at 0x\(String(trojanAddr, radix: 16))")
            return
        }
        NSLog("[bashExec] ✓ remote_writeStr succeeded")

        // ── CALL system() IN REMOTE PROCESS ──
        NSLog("[bashExec] ▶ do_remote_call_stable(timeout=10000, \"system\", 0x%llx)…", trojanAddr)
        let t0 = CFAbsoluteTimeGetCurrent()
        let result = do_remote_call_stable(10000, "system",
                                            trojanAddr, 0, 0, 0, 0, 0, 0, 0)
        let t1 = CFAbsoluteTimeGetCurrent()

        NSLog("[bashExec] ◀ system() returned: 0x%llx (%llu) in %.3fs", result, result, t1 - t0)
        DebugLog.log("[bashExec] system()=0x\(String(result, radix: 16)) (\(result)) in \(String(format: "%.3f", t1 - t0))s")

        // Small delay to let output file finish writing
        usleep(100_000) // 100ms

        // ── READ OUTPUT FILE ──
        NSLog("[bashExec] ▶ Reading output from %@…", tmpOut)

        // Check if file exists first
        let fileExists = FileManager.default.fileExists(atPath: tmpOut)
        NSLog("[bashExec]   File exists: %@", fileExists ? "YES" : "NO")

        if fileExists,
           let data = FileManager.default.contents(atPath: tmpOut),
           let output = String(data: data, encoding: .utf8) {
            NSLog("[bashExec]   Raw output: %d bytes", data.count)
            // Clean up temp file
            try? FileManager.default.removeItem(atPath: tmpOut)

            // Parse: last line is the exit code
            var lines = output.components(separatedBy: "\n")
            var exitCode = "?"
            // Find the exit code (last non-empty line)
            while let last = lines.last, last.trimmingCharacters(in: .whitespaces).isEmpty {
                lines.removeLast()
            }
            if let last = lines.last, last.allSatisfy({ $0.isNumber }) {
                exitCode = last
                lines.removeLast()
            }

            var text = lines.joined(separator: "\n")
            if !text.isEmpty && exitCode != "0" {
                text += "\n[exit code: \(exitCode)]"
            }
            if text.isEmpty { text = "(no output, exit code \(exitCode))" }

            if text.count > 20_000 {
                text = String(text.prefix(20_000)) + "\n[truncated — \(text.count) total chars]"
            }

            let totalTime = CFAbsoluteTimeGetCurrent() - startTime
            NSLog("[bashExec] ✓ DONE: %d chars, exit=%@, total=%.2fs", text.count, exitCode, totalTime)
            DebugLog.log("[bashExec] ✓ DONE: \(text.count) chars, exit=\(exitCode), total=\(String(format: "%.2f", totalTime))s")
            DebugLog.log("[bashExec] Output preview: \(text.prefix(500))")
            once.resume(text)
        } else {
            // Couldn't read output file — try POSIX read as fallback
            NSLog("[bashExec] ⚠ FileManager couldn't read %@, trying POSIX open…", tmpOut)
            DebugLog.log("[bashExec] ⚠ Could not read output file \(tmpOut), trying POSIX")
            let fd = open(tmpOut, O_RDONLY)
            NSLog("[bashExec]   POSIX open() fd=%d (errno=%d: %s)", fd, errno,
                  fd < 0 ? strerror(errno) : "ok")
            if fd >= 0 {
                var buf = [UInt8](repeating: 0, count: 20_001)
                let n = read(fd, &buf, 20_000)
                close(fd)
                unlink(tmpOut)
                if n > 0 {
                    let text = String(bytes: buf[0..<n], encoding: .utf8) ?? "(binary output, \(n) bytes)"
                    let totalTime = CFAbsoluteTimeGetCurrent() - startTime
                    NSLog("[bashExec] ✓ POSIX read: %d bytes, total=%.2fs", n, totalTime)
                    once.resume(text)
                    return
                }
                NSLog("[bashExec]   POSIX read returned %d bytes", n)
            }

            let totalTime = CFAbsoluteTimeGetCurrent() - startTime
            NSLog("[bashExec] ⚠ No output file. system() returned 0x%llx. total=%.2fs", result, totalTime)
            NSLog("[bashExec]   Possible causes: /tmp not writable from target, command failed silently, or target process lacks shell")
            DebugLog.log("[bashExec] ⚠ No output. system()=0x\(String(result, radix: 16)) total=\(String(format: "%.2f", totalTime))s")
            once.resume("Command executed (system() returned \(result)). Output file not readable — the command may not have produced output, or /tmp may not be writable from the target process.")
        }
    }

    // MARK: - grep

    private func grepSearch(pattern: String, directory: String) -> String {
        guard !pattern.isEmpty else { return "Error: pattern required" }
        DebugLog.log("grepSearch: pattern=\(pattern) dir=\(directory)")

        guard let enumerator = FileManager.default.enumerator(atPath: directory) else {
            return "Cannot enumerate \(directory)"
        }

        var results: [String] = []
        let maxResults = 100
        let maxFileSize = 500_000 // skip large files

        for case let name as String in enumerator {
            if results.count >= maxResults { break }

            let fullPath = (directory as NSString).appendingPathComponent(name)
            // Skip directories and large/binary files
            var isDir: ObjCBool = false
            FileManager.default.fileExists(atPath: fullPath, isDirectory: &isDir)
            if isDir.boolValue { continue }

            guard let attrs = try? FileManager.default.attributesOfItem(atPath: fullPath),
                  let size = attrs[.size] as? Int,
                  size < maxFileSize else { continue }

            guard let data = FileManager.default.contents(atPath: fullPath),
                  let text = String(data: data, encoding: .utf8) else { continue }

            let lines = text.components(separatedBy: "\n")
            for (lineNum, line) in lines.enumerated() {
                if line.localizedCaseInsensitiveContains(pattern) {
                    results.append("\(fullPath):\(lineNum + 1): \(String(line.prefix(200)))")
                    if results.count >= maxResults {
                        results.append("... (limited to \(maxResults) results)")
                        break
                    }
                }
            }
        }

        DebugLog.log("  → grep found \(results.count) matches")
        return results.isEmpty
            ? "No matches for '\(pattern)' in \(directory)"
            : results.joined(separator: "\n")
    }

    // MARK: - head / tail

    private func headFile(path: String, lines count: Int) -> String {
        guard !path.isEmpty else { return "Error: path required" }
        guard let data = FileManager.default.contents(atPath: path),
              let text = String(data: data, encoding: .utf8) else {
            return readFile(path: path) // fallback to full read with POSIX
        }
        let lines = text.components(separatedBy: "\n")
        let taken = lines.prefix(count)
        return taken.enumerated().map { "\($0.offset + 1): \($0.element)" }.joined(separator: "\n")
    }

    private func tailFile(path: String, lines count: Int) -> String {
        guard !path.isEmpty else { return "Error: path required" }
        guard let data = FileManager.default.contents(atPath: path),
              let text = String(data: data, encoding: .utf8) else {
            return readFile(path: path)
        }
        let lines = text.components(separatedBy: "\n")
        let start = max(0, lines.count - count)
        let taken = lines[start...]
        return taken.enumerated().map { "\(start + $0.offset + 1): \($0.element)" }.joined(separator: "\n")
    }

    // MARK: - process_list

    private func processList() -> String {
        // Native sysctl-based process list — no shell needed
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0

        // First call: get buffer size
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0 else {
            return "Error: sysctl KERN_PROC_ALL size failed (errno \(errno))"
        }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)

        // Second call: fill buffer
        guard sysctl(&mib, UInt32(mib.count), &procs, &size, nil, 0) == 0 else {
            return "Error: sysctl KERN_PROC_ALL failed (errno \(errno))"
        }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        var entries: [(pid: Int32, name: String)] = []

        for i in 0..<actualCount {
            let pid = procs[i].kp_proc.p_pid
            let name = extractProcName(&procs[i])
            entries.append((pid: pid, name: name))
        }

        entries.sort { $0.pid < $1.pid }

        var lines: [String] = ["PID\tNAME"]
        for e in entries {
            lines.append("\(e.pid)\t\(e.name)")
        }

        DebugLog.log("processList: \(actualCount) processes via sysctl")
        var result = lines.joined(separator: "\n")
        if result.count > 20_000 {
            result = String(result.prefix(20_000)) + "\n[truncated]"
        }
        return result
    }

    /// Safely extract process name from kinfo_proc's p_comm tuple
    private func extractProcName(_ info: inout kinfo_proc) -> String {
        return withUnsafeBytes(of: &info.kp_proc.p_comm) { rawBuf in
            guard let base = rawBuf.baseAddress?.assumingMemoryBound(to: CChar.self) else {
                return "?"
            }
            // String(cString:) reads until the null terminator,
            // which is guaranteed within the p_comm buffer.
            return String(cString: base)
        }
    }

    /// Find a PID by process name using sysctl (no shell needed)
    private func findPid(byName name: String) -> pid_t? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0 else { return nil }
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, UInt32(mib.count), &procs, &size, nil, 0) == 0 else { return nil }
        let actual = size / MemoryLayout<kinfo_proc>.stride

        for i in 0..<actual {
            let procName = extractProcName(&procs[i])
            // Match by exact name or case-insensitive contains
            if procName == name || procName.localizedCaseInsensitiveContains(name) {
                return procs[i].kp_proc.p_pid
            }
        }
        return nil
    }

    // MARK: - device_info

    @MainActor
    private func deviceInfo() async -> String {
        let device = UIDevice.current
        let proc   = ProcessInfo.processInfo

        var lines: [String] = []
        lines.append("Device: \(device.model)")
        lines.append("Name: \(device.name)")
        lines.append("System: \(device.systemName) \(device.systemVersion)")
        lines.append("Processors: \(proc.processorCount) cores")
        lines.append("RAM: \(proc.physicalMemory / (1024*1024)) MB")
        lines.append("Uptime: \(Int(proc.systemUptime))s")

        // Disk space
        if let attrs = try? FileManager.default.attributesOfFileSystem(forPath: "/") {
            if let total = attrs[.systemSize] as? Int64 {
                lines.append("Disk total: \(total / (1024*1024*1024)) GB")
            }
            if let free = attrs[.systemFreeSize] as? Int64 {
                lines.append("Disk free: \(free / (1024*1024*1024)) GB")
            }
        }

        // Sandbox status
        let sbx = SandboxManager.shared.status
        lines.append("Sandbox: \(sbx.label)")

        // Battery
        device.isBatteryMonitoringEnabled = true
        let level = device.batteryLevel
        if level >= 0 {
            lines.append("Battery: \(Int(level * 100))%")
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - open_url

    @MainActor
    private func openURL(_ urlString: String) async -> String {
        guard !urlString.isEmpty else { return "Error: url required" }
        guard let url = URL(string: urlString) else { return "Error: invalid URL" }

        if await UIApplication.shared.canOpenURL(url) {
            await UIApplication.shared.open(url)
            return "Opened \(urlString)"
        } else {
            return "Error: cannot open URL \(urlString)"
        }
    }

    // MARK: - remote_call

    /// Known safe processes for remote_call
    private let knownProcesses = ["SpringBoard", "launchd", "backboardd", "mediaserverd"]

    private func remoteCall(process: String, function: String, args: [AnyJSON]) async -> String {
        guard !process.isEmpty else { return "Error: process name required" }
        guard !function.isEmpty else { return "Error: function name required" }

        // Check sandbox on main actor
        let isUsable = await MainActor.run { SandboxManager.shared.status.isUsable }
        guard isUsable else {
            return "Error: sandbox escape required for remote_call"
        }

        // Block obviously dangerous function names
        let blocked = ["exit", "abort", "_exit", "kill", "reboot", "shutdown"]
        if blocked.contains(function) {
            return "Error: '\(function)' is blocked for safety"
        }

        DebugLog.log("remoteCall: process=\(process) func=\(function) args=\(args.count)")

        // Parse up to 8 uint64 arguments ahead of time
        var x: [UInt64] = Array(repeating: 0, count: 8)
        for (i, arg) in args.prefix(8).enumerated() {
            if let n = arg.uint64Value {
                x[i] = n
            } else if let s = arg.string {
                if s.hasPrefix("0x"), let val = UInt64(s.dropFirst(2), radix: 16) {
                    x[i] = val
                } else if let val = UInt64(s) {
                    x[i] = val
                }
            }
        }

        // Run entirely on a background thread with a timeout.
        // Use NSLock + flag to ensure the continuation is resumed exactly once.
        let localX = x
        let localProcess = process
        let localFunction = function

        return await withCheckedContinuation { continuation in
            let lock = NSLock()
            var resumed = false

            func safeResume(_ value: String) {
                lock.lock()
                defer { lock.unlock() }
                guard !resumed else { return }
                resumed = true
                continuation.resume(returning: value)
            }

            DispatchQueue.global(qos: .userInitiated).async {
                var initOk = false
                defer {
                    if initOk {
                        DebugLog.log("  → remote_call: destroying connection")
                        destroy_remote_call()
                    }
                }

                // Step 1: init — Mach task port attachment + thread hijacking
                DebugLog.log("  → remote_call: init_remote_call(\(localProcess))...")
                let initRet = init_remote_call(localProcess, true)
                guard initRet == 0 else {
                    DebugLog.log("  → remote_call: init failed with \(initRet)")
                    safeResume("Error: failed to attach to process '\(localProcess)' (code \(initRet)). Make sure the process is running and the sandbox escape is active.")
                    return
                }
                initOk = true
                DebugLog.log("  → remote_call: init succeeded")

                // Step 2: call the function
                DebugLog.log("  → remote_call: calling \(localFunction)...")
                let result = do_remote_call_stable(5000, localFunction,
                                                   localX[0], localX[1], localX[2], localX[3],
                                                   localX[4], localX[5], localX[6], localX[7])

                DebugLog.log("  → remote_call result: \(result) (0x\(String(result, radix: 16)))")
                safeResume("Result: \(result) (0x\(String(result, radix: 16)))")
            }

            // Timeout: if it takes more than 15 seconds, give up
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 15) {
                safeResume("Error: remote_call timed out after 15s. The target process may not be reachable.")
            }
        }
    }

    // MARK: - sqlite_query

    private func sqliteQuery(dbPath: String, query: String) -> String {
        guard !dbPath.isEmpty else { return "Error: database path required" }
        guard !query.isEmpty else { return "Error: query required" }

        // Safety: block destructive SQL
        let upper = query.uppercased().trimmingCharacters(in: .whitespaces)
        let destructive = ["DROP ", "DELETE ", "UPDATE ", "INSERT ", "ALTER ", "CREATE ", "REPLACE ", "ATTACH "]
        for d in destructive where upper.hasPrefix(d) {
            return "Error: only SELECT queries are allowed for safety. Use: SELECT ..."
        }

        DebugLog.log("sqliteQuery: db=\(dbPath) query=\(query.prefix(100))")

        var db: OpaquePointer?
        // Open read-only
        let openFlags = SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX
        guard sqlite3_open_v2(dbPath, &db, openFlags, nil) == SQLITE_OK else {
            let err = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            sqlite3_close(db)
            return "Error opening database: \(err)"
        }
        defer { sqlite3_close(db) }

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            let err = String(cString: sqlite3_errmsg(db))
            return "SQL error: \(err)"
        }
        defer { sqlite3_finalize(stmt) }

        let colCount = Int(sqlite3_column_count(stmt))
        var headers: [String] = []
        for i in 0..<colCount {
            headers.append(String(cString: sqlite3_column_name(stmt, Int32(i))))
        }

        var rows: [String] = [headers.joined(separator: "\t")]
        var rowCount = 0
        let maxRows = 200

        while sqlite3_step(stmt) == SQLITE_ROW {
            var cols: [String] = []
            for i in 0..<colCount {
                let idx = Int32(i)
                switch sqlite3_column_type(stmt, idx) {
                case SQLITE_NULL:
                    cols.append("NULL")
                case SQLITE_INTEGER:
                    cols.append("\(sqlite3_column_int64(stmt, idx))")
                case SQLITE_FLOAT:
                    cols.append("\(sqlite3_column_double(stmt, idx))")
                case SQLITE_TEXT:
                    if let cStr = sqlite3_column_text(stmt, idx) {
                        let s = String(cString: cStr)
                        cols.append(s.count > 200 ? String(s.prefix(200)) + "…" : s)
                    } else {
                        cols.append("")
                    }
                case SQLITE_BLOB:
                    let size = sqlite3_column_bytes(stmt, idx)
                    cols.append("<blob \(size) bytes>")
                default:
                    cols.append("?")
                }
            }
            rows.append(cols.joined(separator: "\t"))
            rowCount += 1
            if rowCount >= maxRows {
                rows.append("... (limited to \(maxRows) rows)")
                break
            }
        }

        DebugLog.log("  → sqlite: \(rowCount) rows, \(colCount) cols")
        return rows.count <= 1
            ? "Query returned no results."
            : rows.joined(separator: "\n")
    }

    // MARK: - installed_apps

    private func installedApps() -> String {
        DebugLog.log("installedApps")
        let bundleFolder = "/private/var/containers/Bundle/Application"
        let fm = FileManager.default

        guard let bundles = try? fm.contentsOfDirectory(atPath: bundleFolder) else {
            return "Error: cannot read \(bundleFolder). Is sandbox escape active?"
        }

        var apps: [(name: String, bundleID: String, version: String, path: String, size: Int64)] = []

        for uuid in bundles {
            let uuidPath = bundleFolder + "/" + uuid
            guard let contents = try? fm.contentsOfDirectory(atPath: uuidPath) else { continue }
            for item in contents where item.hasSuffix(".app") {
                let appPath = uuidPath + "/" + item
                let infoPath = appPath + "/Info.plist"
                guard let info = NSDictionary(contentsOfFile: infoPath) else { continue }

                let executable = info["CFBundleExecutable"] as? String ?? ""
                if executable.isEmpty { continue }

                let bundleID = info["CFBundleIdentifier"] as? String ?? "?"
                let name = (info["CFBundleDisplayName"] as? String)
                    ?? (info["CFBundleName"] as? String)
                    ?? (item as NSString).deletingPathExtension
                let version = (info["CFBundleShortVersionString"] as? String ?? "?")
                    + " (\(info["CFBundleVersion"] as? String ?? "?"))"

                // Calculate app bundle size
                var totalSize: Int64 = 0
                if let enumerator = fm.enumerator(at: URL(fileURLWithPath: appPath),
                                                   includingPropertiesForKeys: [.fileSizeKey]) {
                    for case let fileURL as URL in enumerator {
                        if let size = (try? fileURL.resourceValues(forKeys: [.fileSizeKey]))?.fileSize {
                            totalSize += Int64(size)
                        }
                    }
                }

                apps.append((name: name, bundleID: bundleID, version: version,
                             path: appPath, size: totalSize))
                break // only first .app in each UUID folder
            }
        }

        apps.sort { $0.name.lowercased() < $1.name.lowercased() }

        DebugLog.log("  → found \(apps.count) apps")

        var lines: [String] = ["Found \(apps.count) installed apps:\n"]
        for app in apps {
            let sizeMB = app.size / (1024 * 1024)
            lines.append("• \(app.name)  [\(app.bundleID)]")
            lines.append("  v\(app.version)  \(sizeMB)MB")
            lines.append("  \(app.path)")
        }

        var result = lines.joined(separator: "\n")
        if result.count > 20_000 {
            result = String(result.prefix(20_000)) + "\n[truncated]"
        }
        return result
    }

    // MARK: - read_plist

    private func readPlist(path: String) -> String {
        guard !path.isEmpty else { return "Error: path required" }
        DebugLog.log("readPlist: \(path)")

        // Try reading as NSDictionary first (handles binary + XML plists)
        if let dict = NSDictionary(contentsOfFile: path) {
            return formatPlistObject(dict, indent: 0)
        }

        // Try NSArray
        if let arr = NSArray(contentsOfFile: path) {
            return formatPlistObject(arr, indent: 0)
        }

        // Try raw Data → PropertyListSerialization
        guard let data = FileManager.default.contents(atPath: path) else {
            return "Error: cannot read file at \(path)"
        }
        do {
            let obj = try PropertyListSerialization.propertyList(from: data, format: nil)
            if let dict = obj as? NSDictionary {
                return formatPlistObject(dict, indent: 0)
            } else if let arr = obj as? NSArray {
                return formatPlistObject(arr, indent: 0)
            }
            return "\(obj)"
        } catch {
            return "Error: not a valid plist — \(error.localizedDescription)"
        }
    }

    private func formatPlistObject(_ obj: Any, indent: Int) -> String {
        let pad = String(repeating: "  ", count: indent)
        switch obj {
        case let dict as NSDictionary:
            if dict.count == 0 { return "\(pad){}" }
            var lines: [String] = []
            let sorted = dict.allKeys.compactMap { $0 as? String }.sorted()
            for key in sorted {
                let val = dict[key]!
                let valStr = formatPlistObject(val, indent: indent + 1)
                if valStr.contains("\n") {
                    lines.append("\(pad)\(key):")
                    lines.append(valStr)
                } else {
                    lines.append("\(pad)\(key): \(valStr.trimmingCharacters(in: .whitespaces))")
                }
            }
            return lines.joined(separator: "\n")
        case let arr as NSArray:
            if arr.count == 0 { return "\(pad)[]" }
            var lines: [String] = []
            for (i, item) in arr.enumerated() {
                let s = formatPlistObject(item, indent: indent + 1)
                if s.contains("\n") {
                    lines.append("\(pad)[\(i)]:")
                    lines.append(s)
                } else {
                    lines.append("\(pad)[\(i)]: \(s.trimmingCharacters(in: .whitespaces))")
                }
            }
            return lines.joined(separator: "\n")
        case let data as Data:
            if data.count <= 64 {
                return "\(pad)<\(data.map { String(format: "%02x", $0) }.joined())>"
            }
            return "\(pad)<data: \(data.count) bytes>"
        case let date as Date:
            return "\(pad)\(date)"
        case let num as NSNumber:
            // Check if it's a boolean
            if CFGetTypeID(num) == CFBooleanGetTypeID() {
                return "\(pad)\(num.boolValue)"
            }
            return "\(pad)\(num)"
        case let str as String:
            return "\(pad)\(str)"
        default:
            return "\(pad)\(obj)"
        }
    }

    // MARK: - memory_dump

    private func memoryDump(process: String, address addressStr: String, size: Int) async -> String {
        guard !process.isEmpty else { return "Error: process name is required" }

        // Parse address — support hex (0x...) and decimal
        let addr: UInt64
        if addressStr.hasPrefix("0x") || addressStr.hasPrefix("0X") {
            guard let val = UInt64(addressStr.dropFirst(2), radix: 16) else {
                return "Error: invalid hex address '\(addressStr)'"
            }
            addr = val
        } else {
            guard let val = UInt64(addressStr) else {
                return "Error: invalid address '\(addressStr)'"
            }
            addr = val
        }

        guard addr != 0 else { return "Error: cannot read from NULL (address 0x0)" }

        let clampedSize = min(max(size, 16), 4096)

        // Check sandbox escape
        let escaped = await MainActor.run { SandboxManager.shared.status.isUsable }
        guard escaped else { return "Error: sandbox escape not active — memory_dump requires kernel exploit" }

        return await withCheckedContinuation { (cont: CheckedContinuation<String, Never>) in
            let lock = NSLock()
            var resumed = false
            func resumeOnce(_ value: String) {
                lock.lock()
                defer { lock.unlock() }
                guard !resumed else { return }
                resumed = true
                cont.resume(returning: value)
            }

            // Timeout
            DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
                resumeOnce("Error: memory_dump timed out after 15s")
            }

            DispatchQueue.global(qos: .userInitiated).async {
                DebugLog.log("[MemDump] Attaching to \(process)…")
                let initRet = init_remote_call(process, false)
                guard initRet == 0 else {
                    DebugLog.log("[MemDump] init_remote_call failed: \(initRet)")
                    resumeOnce("Error: could not attach to process '\(process)' (init returned \(initRet)). Is the process running?")
                    return
                }
                defer { destroy_remote_call() }

                DebugLog.log("[MemDump] Reading \(clampedSize) bytes at 0x\(String(addr, radix: 16))…")
                var buffer = [UInt8](repeating: 0, count: clampedSize)
                let ok = remote_read(addr, &buffer, UInt64(clampedSize))

                guard ok else {
                    DebugLog.log("[MemDump] remote_read failed")
                    resumeOnce("Error: remote_read failed — address 0x\(String(addr, radix: 16)) may be unmapped or unreadable")
                    return
                }

                // Format hex dump: offset | hex bytes | ASCII
                var lines: [String] = []
                lines.append("Memory dump of \(process) at 0x\(String(addr, radix: 16)), \(clampedSize) bytes:")
                lines.append("")

                for row in stride(from: 0, to: clampedSize, by: 16) {
                    let end = min(row + 16, clampedSize)
                    let offsetStr = String(format: "%08x", UInt(addr) + UInt(row))

                    // Hex part
                    var hexParts: [String] = []
                    for i in row..<end {
                        hexParts.append(String(format: "%02x", buffer[i]))
                    }
                    // Pad if less than 16 bytes
                    while hexParts.count < 16 { hexParts.append("  ") }
                    let hexStr = hexParts[0..<8].joined(separator: " ") + "  " + hexParts[8..<16].joined(separator: " ")

                    // ASCII part
                    var ascii = ""
                    for i in row..<end {
                        let b = buffer[i]
                        ascii.append(b >= 0x20 && b < 0x7f ? Character(UnicodeScalar(b)) : ".")
                    }

                    lines.append("\(offsetStr)  \(hexStr)  |\(ascii)|")
                }

                let result = lines.joined(separator: "\n")
                DebugLog.log("[MemDump] Success — \(lines.count - 2) rows")
                resumeOnce(result)
            }
        }
    }

    // MARK: - app_control

    private func appControl(action: String, target: String) async -> String {
        guard !action.isEmpty else {
            return "Error: action is required. Use: freeze, unfreeze, kill, or launch"
        }
        guard !target.isEmpty else {
            return "Error: target is required (app name, process name, PID, or bundle ID for launch)"
        }

        switch action.lowercased() {
        case "freeze":
            return freezeOrResume(target: target, signal: "STOP", verb: "Frozen")
        case "unfreeze", "resume", "thaw":
            return freezeOrResume(target: target, signal: "CONT", verb: "Resumed")
        case "kill", "terminate":
            return freezeOrResume(target: target, signal: "TERM", verb: "Terminated")
        case "launch", "open":
            return await launchApp(bundleId: target)
        default:
            return "Error: unknown action '\(action)'. Use: freeze, unfreeze, kill, or launch"
        }
    }

    private func freezeOrResume(target: String, signal: String, verb: String) -> String {
        // Resolve the target to a PID
        let targetPid: pid_t
        if target.allSatisfy(\.isNumber), let p = Int32(target) {
            targetPid = p
        } else if let p = findPid(byName: target) {
            targetPid = p
        } else {
            return "Error: no running process found matching '\(target)'"
        }

        // Map signal name to signal number
        let sig: Int32
        switch signal {
        case "STOP": sig = SIGSTOP
        case "CONT": sig = SIGCONT
        case "TERM": sig = SIGTERM
        default:     sig = SIGTERM
        }

        // Native kill() syscall — no shell needed
        let ret = kill(targetPid, sig)
        if ret == 0 {
            DebugLog.log("[AppControl] \(verb) PID \(targetPid) (target: \(target))")
            return "\(verb) process '\(target)' (PID \(targetPid))"
        } else {
            let err = String(cString: strerror(errno))
            return "Error: kill(\(targetPid), \(signal)) failed — \(err)"
        }
    }

    private func launchApp(bundleId: String) async -> String {
        // Use SBSLaunchApplicationWithIdentifier via remote_call if sandbox is escaped
        let escaped = await MainActor.run { SandboxManager.shared.status.isUsable }
        if escaped {
            // Try launching via SpringBoard's private API
            let launched = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    let initRet = init_remote_call("SpringBoard", true)
                    guard initRet == 0 else {
                        cont.resume(returning: false)
                        return
                    }
                    defer { destroy_remote_call() }

                    // Write bundle ID to shared memory
                    guard remote_writeStr(g_RC_trojanMem, bundleId) else {
                        cont.resume(returning: false)
                        return
                    }

                    // Call SBSLaunchApplicationWithIdentifier(bundleId, false)
                    let result = do_remote_call_stable(5000,
                        "SBSLaunchApplicationWithIdentifier",
                        g_RC_trojanMem, 0, 0, 0, 0, 0, 0, 0)
                    cont.resume(returning: result == 0)
                }
            }
            if launched {
                DebugLog.log("[AppControl] Launched \(bundleId) via SpringBoard remote_call")
                return "Launched app: \(bundleId)"
            }
        }

        // Fall back to opening via URL (for apps with URL schemes)
        let urlStr = "\(bundleId)://"
        let opened = await MainActor.run {
            guard let url = URL(string: urlStr) else { return false }
            UIApplication.shared.open(url, options: [:], completionHandler: nil)
            return true
        }

        if opened {
            DebugLog.log("[AppControl] Launched \(bundleId) via URL scheme")
            return "Attempted to launch \(bundleId) via URL scheme '\(urlStr)'"
        }

        return "Error: could not launch '\(bundleId)' — uiopen failed and URL scheme didn't work"
    }

    // MARK: - copy_move_file

    private func copyMoveFile(source: String, destination: String, move: Bool) -> String {
        guard !source.isEmpty else { return "Error: source path required" }
        guard !destination.isEmpty else { return "Error: destination path required" }

        for blocked in writeBlocklist where destination.hasPrefix(blocked) {
            return "Error: \(blocked) is blocked for safety"
        }

        let fm = FileManager.default
        guard fm.fileExists(atPath: source) else {
            return "Error: source file does not exist: \(source)"
        }

        // If destination exists, remove it first
        if fm.fileExists(atPath: destination) {
            do {
                try fm.removeItem(atPath: destination)
            } catch {
                return "Error removing existing destination: \(error.localizedDescription)"
            }
        }

        // Make sure destination directory exists
        let destDir = (destination as NSString).deletingLastPathComponent
        if !fm.fileExists(atPath: destDir) {
            do {
                try fm.createDirectory(atPath: destDir, withIntermediateDirectories: true)
            } catch {
                return "Error creating destination directory: \(error.localizedDescription)"
            }
        }

        do {
            if move {
                try fm.moveItem(atPath: source, toPath: destination)
                DebugLog.log("[CopyMove] Moved \(source) → \(destination)")
                return "Moved \(source) → \(destination)"
            } else {
                try fm.copyItem(atPath: source, toPath: destination)
                let size = (try? fm.attributesOfItem(atPath: destination)[.size] as? Int) ?? 0
                DebugLog.log("[CopyMove] Copied \(source) → \(destination) (\(size) bytes)")
                return "Copied \(source) → \(destination) (\(size) bytes)"
            }
        } catch {
            return "Error \(move ? "moving" : "copying"): \(error.localizedDescription)"
        }
    }

    /// Describe why a filesystem operation failed, with a hint if the path has a known symlink alias.
    private func describe(_ error: Error, at path: String) -> String {
        let ns = error as NSError
        let fm = FileManager.default
        var reason = ns.localizedDescription

        // Add specific codes
        if ns.domain == NSCocoaErrorDomain {
            switch ns.code {
            case 260: reason = "file does not exist"
            case 257: reason = "permission denied (sandbox or Data Protection)"
            case 513: reason = "permission denied (sandbox)"
            case 640: reason = "file is in a directory marked no-read"
            default:  break
            }
        }

        // Hint about symlink alternatives
        var hint = ""
        if path.hasPrefix("/var/") {
            let alt = "/private" + path
            if fm.fileExists(atPath: alt) { hint = ". Try \(alt) instead" }
        } else if path.hasPrefix("/tmp/") {
            let alt = "/private" + path
            if fm.fileExists(atPath: alt) { hint = ". Try \(alt) instead" }
        } else if path.hasPrefix("/etc/") {
            let alt = "/private" + path
            if fm.fileExists(atPath: alt) { hint = ". Try \(alt) instead" }
        }

        // Does the path even exist?
        if !fm.fileExists(atPath: path) && hint.isEmpty {
            hint = " (path does not exist in current sandbox)"
        }

        return reason + hint
    }
}
