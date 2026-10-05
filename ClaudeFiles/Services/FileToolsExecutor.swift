import Foundation

final class FileToolsExecutor {

    private let writeBlocklist = ["/System/Library/CoreServices", "/usr/lib", "/bin", "/sbin"]

    func execute(name: String, input: [String: AnyJSON]) async -> String {
        let path      = input["path"]?.string      ?? ""
        let content   = input["content"]?.string   ?? ""
        let directory = input["directory"]?.string ?? ""
        let pattern   = input["pattern"]?.string   ?? ""

        switch name {
        case "read_file":      return readFile(path: path)
        case "write_file":     return writeFile(path: path, content: content)
        case "list_directory": return listDir(path: path)
        case "search_files":   return search(dir: directory, pattern: pattern)
        case "get_file_info":  return fileInfo(path: path)
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
