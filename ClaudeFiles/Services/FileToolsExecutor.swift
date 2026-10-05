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
        if let text = try? String(contentsOfFile: path, encoding: .utf8) {
            return text.count > 20_000
                ? String(text.prefix(20_000)) + "\n[truncated — \(text.count) total chars]"
                : text
        }
        if let data = FileManager.default.contents(atPath: path) {
            return "Binary (\(data.count) bytes). Hex: " +
                data.prefix(128).map { String(format: "%02x", $0) }.joined(separator: " ")
        }
        return "Error: cannot read \(path)"
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
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(atPath: path) else {
            return "Error: cannot list \(path)"
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
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return "Error: cannot get info for \(path)"
        }
        var lines: [String] = []
        if let size = attrs[.size]             as? Int  { lines.append("Size: \(size) bytes") }
        if let mod  = attrs[.modificationDate]          { lines.append("Modified: \(mod)") }
        if let perm = attrs[.posixPermissions] as? Int  { lines.append(String(format: "Permissions: %o", perm)) }
        if let owner = attrs[.ownerAccountName]         { lines.append("Owner: \(owner)") }
        return lines.joined(separator: "\n")
    }
}
