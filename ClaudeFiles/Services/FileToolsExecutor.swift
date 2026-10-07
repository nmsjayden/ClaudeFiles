import Foundation
import UIKit

final class FileToolsExecutor {

    private let writeBlocklist = ["/System/Library/CoreServices", "/usr/lib", "/bin", "/sbin"]

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

    // MARK: - bash_exec (uses C bridge to bypass Swift's iOS popen restriction)

    private func bashExec(command: String) async -> String {
        guard !command.isEmpty else { return "Error: command required" }

        // Block dangerous commands
        let blocked = ["rm -rf /", "mkfs", "dd if=", ":(){ :", "fork bomb"]
        for b in blocked where command.contains(b) {
            return "Error: blocked dangerous command"
        }

        DebugLog.log("bashExec: \(command.prefix(100))")

        var exitCode: Int32 = -1
        guard let cResult = shell_exec(command, &exitCode) else {
            DebugLog.log("  → shell_exec returned NULL")
            return "Error: shell_exec failed (command may not be available on this device)"
        }
        defer { free(cResult) }

        var result = String(cString: cResult)
        if exitCode != 0 { result += "\n[exit code: \(exitCode)]" }
        if result.isEmpty { result = "(no output, exit code \(exitCode))" }

        if result.count > 20_000 {
            result = String(result.prefix(20_000)) + "\n[truncated — \(result.count) total chars]"
        }
        DebugLog.log("  → bash exit=\(exitCode), output=\(result.count)c")
        return result
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
        var pids = [pid_t](repeating: 0, count: 1024)
        let byteCount = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids,
                                       Int32(MemoryLayout<pid_t>.stride * pids.count))
        guard byteCount > 0 else {
            // Fallback to bash
            return "proc_listpids unavailable — use bash_exec with 'ps aux' instead"
        }
        let pidCount = Int(byteCount) / MemoryLayout<pid_t>.stride
        var lines: [String] = ["PID\tNAME"]
        for i in 0..<pidCount {
            let pid = pids[i]
            if pid == 0 { continue }
            var buf = [CChar](repeating: 0, count: 1024)
            proc_name(pid, &buf, UInt32(buf.count))
            let name = String(cString: buf)
            if !name.isEmpty {
                lines.append("\(pid)\t\(name)")
            }
        }
        return lines.joined(separator: "\n")
    }

    // MARK: - device_info

    private func deviceInfo() async -> String {
        let device = await UIDevice.current
        let proc   = ProcessInfo.processInfo

        var lines: [String] = []
        lines.append("Device: \(await device.model)")
        lines.append("Name: \(await device.name)")
        lines.append("System: \(await device.systemName) \(await device.systemVersion)")
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
        let sbx = await SandboxManager.shared.status
        lines.append("Sandbox: \(sbx.label)")

        // Battery
        await device.isBatteryMonitoringEnabled = true
        let level = await device.batteryLevel
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

    private func remoteCall(process: String, function: String, args: [AnyJSON]) async -> String {
        guard !process.isEmpty else { return "Error: process name required" }
        guard !function.isEmpty else { return "Error: function name required" }
        let isUsable = await SandboxManager.shared.status.isUsable
        guard isUsable else {
            return "Error: sandbox escape required for remote_call"
        }

        DebugLog.log("remoteCall: process=\(process) func=\(function) args=\(args.count)")

        // Initialize RemoteCall connection to target process
        let initRet = init_remote_call(process, true)
        guard initRet == 0 else {
            return "Error: failed to attach to process '\(process)' (code \(initRet)). Is it running?"
        }

        // Parse up to 8 uint64 arguments
        var x: [UInt64] = Array(repeating: 0, count: 8)
        for (i, arg) in args.prefix(8).enumerated() {
            if let n = arg.uint64Value {
                x[i] = n
            } else if let s = arg.string {
                // If it's a hex string like "0x1234", parse it
                if s.hasPrefix("0x"), let val = UInt64(s.dropFirst(2), radix: 16) {
                    x[i] = val
                } else if let val = UInt64(s) {
                    x[i] = val
                }
            }
        }

        let result = do_remote_call_stable(5, function,
                                           x[0], x[1], x[2], x[3],
                                           x[4], x[5], x[6], x[7])

        destroy_remote_call()

        DebugLog.log("  → remote_call result: 0x\(String(result, radix: 16))")
        return "Result: \(result) (0x\(String(result, radix: 16)))"
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
