import Foundation

// MARK: - Tool definitions sent to the API

enum FileTools {
    static let definitions: [ToolDefinition] = [
        ToolDefinition(
            name: "read_file",
            description: "Read the contents of a file at the given absolute path.",
            inputSchema: JSONSchema(
                type: "object",
                properties: ["path": PropertySchema(type: "string", description: "Absolute path to the file")],
                required: ["path"]
            )
        ),
        ToolDefinition(
            name: "write_file",
            description: "Write (or overwrite) content to a file. The user must approve before this executes.",
            inputSchema: JSONSchema(
                type: "object",
                properties: [
                    "path":    PropertySchema(type: "string", description: "Absolute path to write to"),
                    "content": PropertySchema(type: "string", description: "Content to write"),
                ],
                required: ["path", "content"]
            )
        ),
        ToolDefinition(
            name: "list_directory",
            description: "List the contents of a directory.",
            inputSchema: JSONSchema(
                type: "object",
                properties: ["path": PropertySchema(type: "string", description: "Absolute path to the directory")],
                required: ["path"]
            )
        ),
        ToolDefinition(
            name: "search_files",
            description: "Search recursively for files whose names match a pattern.",
            inputSchema: JSONSchema(
                type: "object",
                properties: [
                    "directory": PropertySchema(type: "string", description: "Root directory to search"),
                    "pattern":   PropertySchema(type: "string", description: "Filename substring to match"),
                ],
                required: ["directory", "pattern"]
            )
        ),
        ToolDefinition(
            name: "get_file_info",
            description: "Get metadata for a file: size, permissions, modification date.",
            inputSchema: JSONSchema(
                type: "object",
                properties: ["path": PropertySchema(type: "string", description: "Absolute path to the file")],
                required: ["path"]
            )
        ),
    ]
}

// MARK: - Executor

/// Runs file tool calls locally.
/// DarkSword's sandbox escape grants this process access to the full filesystem,
/// so standard FileManager calls reach anywhere — no special API needed here.
final class FileToolsExecutor {

    // Paths that are blocked from writes to prevent bricking
    private static let writeBlocklist: [String] = [
        "/System/Library/CoreServices",
        "/usr/lib",
        "/bin",
        "/sbin",
    ]

    func execute(toolName: String, input: [String: JSONValue]) async -> String {
        switch toolName {
        case "read_file":
            return readFile(path: input["path"]?.stringValue ?? "")
        case "write_file":
            return writeFile(
                path:    input["path"]?.stringValue    ?? "",
                content: input["content"]?.stringValue ?? ""
            )
        case "list_directory":
            return listDirectory(path: input["path"]?.stringValue ?? "")
        case "search_files":
            return searchFiles(
                directory: input["directory"]?.stringValue ?? "",
                pattern:   input["pattern"]?.stringValue   ?? ""
            )
        case "get_file_info":
            return getFileInfo(path: input["path"]?.stringValue ?? "")
        default:
            return "Unknown tool: \(toolName)"
        }
    }

    // MARK: - Individual tools

    private func readFile(path: String) -> String {
        guard !path.isEmpty else { return "Error: no path provided" }
        do {
            // Try text first
            let content = try String(contentsOfFile: path, encoding: .utf8)
            let preview = content.count > 20_000
                ? String(content.prefix(20_000)) + "\n\n[truncated — \(content.count) chars total]"
                : content
            return preview
        } catch {
            // Try binary and report
            if let data = FileManager.default.contents(atPath: path) {
                return "Binary file (\(data.count) bytes). First 256 bytes hex:\n" +
                    data.prefix(256).map { String(format: "%02x", $0) }.joined(separator: " ")
            }
            return "Error reading \(path): \(error.localizedDescription)"
        }
    }

    private func writeFile(path: String, content: String) -> String {
        guard !path.isEmpty else { return "Error: no path provided" }

        for blocked in Self.writeBlocklist {
            if path.hasPrefix(blocked) {
                return "Error: writes to \(blocked) are blocked for safety."
            }
        }

        // Back up existing file first
        let fm = FileManager.default
        if fm.fileExists(atPath: path) {
            let backup = path + ".claudebackup"
            try? fm.copyItem(atPath: path, toPath: backup)
        }

        do {
            try content.write(toFile: path, atomically: true, encoding: .utf8)
            return "Written \(content.utf8.count) bytes to \(path)"
        } catch {
            return "Error writing \(path): \(error.localizedDescription)"
        }
    }

    private func listDirectory(path: String) -> String {
        guard !path.isEmpty else { return "Error: no path provided" }
        do {
            let fm = FileManager.default
            let items = try fm.contentsOfDirectory(atPath: path)
            let annotated: [String] = items.map { name in
                let full = (path as NSString).appendingPathComponent(name)
                var isDir: ObjCBool = false
                fm.fileExists(atPath: full, isDirectory: &isDir)
                return isDir.boolValue ? "\(name)/" : name
            }
            return annotated.sorted().joined(separator: "\n")
        } catch {
            return "Error listing \(path): \(error.localizedDescription)"
        }
    }

    private func searchFiles(directory: String, pattern: String) -> String {
        guard !directory.isEmpty, !pattern.isEmpty else { return "Error: directory and pattern required" }
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: directory) else {
            return "Cannot enumerate \(directory)"
        }
        var matches: [String] = []
        for case let name as String in enumerator {
            if name.localizedCaseInsensitiveContains(pattern) {
                matches.append((directory as NSString).appendingPathComponent(name))
            }
            if matches.count >= 200 { matches.append("... (limited to 200 results)"); break }
        }
        return matches.isEmpty ? "No files matching '\(pattern)' found in \(directory)" : matches.joined(separator: "\n")
    }

    private func getFileInfo(path: String) -> String {
        guard !path.isEmpty else { return "Error: no path provided" }
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            var lines: [String] = []
            if let size = attrs[.size] as? Int       { lines.append("Size: \(size) bytes") }
            if let mod  = attrs[.modificationDate]   { lines.append("Modified: \(mod)") }
            if let type = attrs[.type] as? FileAttributeType { lines.append("Type: \(type.rawValue)") }
            if let perm = attrs[.posixPermissions] as? Int {
                lines.append(String(format: "Permissions: %o", perm))
            }
            if let owner = attrs[.ownerAccountName] { lines.append("Owner: \(owner)") }
            return lines.joined(separator: "\n")
        } catch {
            return "Error: \(error.localizedDescription)"
        }
    }
}
