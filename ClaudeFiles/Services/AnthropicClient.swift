import Foundation

final class AnthropicClient {
    private let apiURL    = URL(string: "https://api.anthropic.com/v1/messages")!
    private let sessionId = UUID().uuidString.lowercased()

    @MainActor
    func sendStreaming(
        messages: [ChatMessage],
        system: String,
        accessToken: String,
        onEvent: @escaping (StreamEvent) -> Void
    ) async throws {
        var token = accessToken
        var rateLimitRetries = 0
        let maxRateLimitRetries = 2

        while true {
            do {
                try await _sendStreaming(messages: messages, system: system,
                                         accessToken: token, onEvent: onEvent)
                return
            } catch let err as APIError {
                switch err {
                case .authExpired:
                    DebugLog.log("[API] 401 — attempting token refresh")
                    guard let newToken = await AuthManager.shared.refreshAccessToken() else {
                        throw APIError.serverError("Session expired. Please sign out and sign back in.")
                    }
                    token = newToken
                    continue

                case .rateLimited(let retryAfter):
                    rateLimitRetries += 1
                    if rateLimitRetries > maxRateLimitRetries {
                        throw APIError.serverError("Rate limited after \(maxRateLimitRetries) retries. Please wait a moment.")
                    }
                    let delay = min(retryAfter, 60)
                    DebugLog.log("[API] 429 — waiting \(delay)s (retry \(rateLimitRetries)/\(maxRateLimitRetries))")
                    onEvent(.statusMessage("Rate limited — retrying in \(Int(delay))s…"))
                    try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                    continue

                default:
                    throw err
                }
            }
        }
    }

    @MainActor
    private func _sendStreaming(
        messages: [ChatMessage],
        system: String,
        accessToken: String,
        onEvent: @escaping (StreamEvent) -> Void
    ) async throws {
        let model = SettingsStore.shared.selectedModel

        var components = URLComponents(url: apiURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "beta", value: "true")]
        var req = URLRequest(url: components.url!)
        req.httpMethod = "POST"

        req.setValue("Bearer \(accessToken)",            forHTTPHeaderField: "Authorization")
        req.setValue("application/json",                 forHTTPHeaderField: "Content-Type")
        req.setValue("text/event-stream",                forHTTPHeaderField: "Accept")
        req.setValue("2023-06-01",                       forHTTPHeaderField: "anthropic-version")
        req.setValue("claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14,compact-2026-01-12,prompt-caching-scope-2026-01-05",
                     forHTTPHeaderField: "anthropic-beta")
        req.setValue("true",                             forHTTPHeaderField: "anthropic-dangerous-direct-browser-access")
        req.setValue("claude-cli/2.1.291 (external, cli)", forHTTPHeaderField: "User-Agent")
        req.setValue("cli",                               forHTTPHeaderField: "x-app")
        req.setValue("js",                                forHTTPHeaderField: "x-stainless-lang")
        req.setValue("0.120.0",                             forHTTPHeaderField: "x-stainless-package-version")
        req.setValue("MacOS",                             forHTTPHeaderField: "x-stainless-os")
        req.setValue("arm64",                             forHTTPHeaderField: "x-stainless-arch")
        req.setValue("node",                              forHTTPHeaderField: "x-stainless-runtime")
        req.setValue("v22.14.0",                          forHTTPHeaderField: "x-stainless-runtime-version")
        req.setValue("0",                                 forHTTPHeaderField: "x-stainless-retry-count")
        req.setValue("600",                               forHTTPHeaderField: "x-stainless-timeout")
        req.setValue(UUID().uuidString.lowercased(),      forHTTPHeaderField: "x-client-request-id")
        req.setValue(sessionId,                           forHTTPHeaderField: "x-claude-code-session-id")

        let systemBlocks: [SystemBlock] = [
            SystemBlock(type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude."),
            SystemBlock(type: "text", text: system),
        ]

        let contextMgmt = ContextManagement(edits: [
            CompactEdit(type: "compact_20260112",
                        trigger: CompactTrigger(type: "input_tokens", value: 100_000))
        ])

        let body = RequestBody(model: model, maxTokens: 8192, stream: true,
                               system: systemBlocks, messages: messages,
                               tools: FileToolDefinitions.all,
                               contextManagement: contextMgmt)
        req.httpBody = try JSONEncoder().encode(body)

        DebugLog.log("API send: model=\(model), messages=\(messages.count)")

        let (bytes, response) = try await URLSession.shared.bytes(for: req)
        guard let http = response as? HTTPURLResponse else {
            DebugLog.log("No HTTPURLResponse")
            throw APIError.invalidResponse
        }

        DebugLog.log("HTTP status: \(http.statusCode)")

        if http.statusCode == 401 {
            var buf = Data()
            for try await byte in bytes { buf.append(byte) }
            let raw = String(data: buf, encoding: .utf8) ?? "<non-utf8>"
            DebugLog.log("Auth expired: \(raw.prefix(500))")
            throw APIError.authExpired
        }

        if http.statusCode == 429 {
            var buf = Data()
            for try await byte in bytes { buf.append(byte) }
            let raw = String(data: buf, encoding: .utf8) ?? "<non-utf8>"
            DebugLog.log("Rate limited: \(raw.prefix(500))")
            // Check if it's a credits_required error vs a normal rate limit
            if raw.contains("credits_required") {
                // Parse model name from error if possible
                let modelName = Self.extractField(from: raw, field: "model_display_name") ?? "This model"
                throw APIError.creditsRequired(modelName)
            }
            // Normal rate limit — throw retryable error with retry-after
            let retryAfter = http.value(forHTTPHeaderField: "retry-after")
                .flatMap(Double.init) ?? 30
            throw APIError.rateLimited(retryAfterSeconds: retryAfter)
        }

        if http.statusCode != 200 {
            var buf = Data()
            for try await byte in bytes { buf.append(byte) }
            let raw = String(data: buf, encoding: .utf8) ?? "<non-utf8>"
            DebugLog.log("Error body: \(raw.prefix(500))")
            throw APIError.serverError("HTTP \(http.statusCode)\n\n\(raw.prefix(2000))")
        }

        // Parse SSE events. Spec: fields separated by \n, events separated by blank line.
        // Field format: "field: value" (one space after colon is optional).
        var currentEvent = ""
        var currentData  = ""
        var eventCount   = 0

        var totalLines = 0
        for try await line in bytes.lines {
            try Task.checkCancellation()
            totalLines += 1

            // Blank line = event boundary
            if line.isEmpty {
                if !currentData.isEmpty {
                    processSSE(event: currentEvent, data: currentData, onEvent: onEvent)
                    eventCount += 1
                }
                currentEvent = ""
                currentData  = ""
                continue
            }

            // SSE comments — skip
            if line.hasPrefix(":") { continue }

            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let field = String(line[..<colonIdx])
            var valueStart = line.index(after: colonIdx)
            if valueStart < line.endIndex && line[valueStart] == " " {
                valueStart = line.index(after: valueStart)
            }
            let value = String(line[valueStart...])

            switch field {
            case "event":
                // New event starting — dispatch previous one if we have it
                // (URLSession.bytes.lines strips the blank-line separator between events)
                if !currentData.isEmpty {
                    processSSE(event: currentEvent, data: currentData, onEvent: onEvent)
                    eventCount += 1
                    currentData = ""
                }
                currentEvent = value
            case "data":
                if currentData.isEmpty {
                    currentData = value
                } else {
                    currentData += "\n" + value
                }
            default:
                break
            }
        }

        // Dispatch any trailing event
        if !currentData.isEmpty {
            processSSE(event: currentEvent, data: currentData, onEvent: onEvent)
            eventCount += 1
        }

        DebugLog.log("Stream done: lines=\(totalLines), events=\(eventCount)")

        if eventCount == 0 {
            throw APIError.serverError("Stream ended with no SSE events received. The connection may have been dropped.")
        }
    }

    private func processSSE(event: String, data: String, onEvent: (StreamEvent) -> Void) {
        guard let payload = data.data(using: .utf8) else { return }
        switch event {
        case "content_block_start":
            if let p = try? JSONDecoder().decode(ContentBlockStartEvent.self, from: payload) {
                if p.content_block.type == "tool_use" {
                    onEvent(.toolUseStart(index: p.index,
                                          id: p.content_block.id ?? "",
                                          name: p.content_block.name ?? ""))
                } else if p.content_block.type == "text" {
                    onEvent(.textStart(index: p.index))
                } else if p.content_block.type == "compaction" {
                    onEvent(.compactionStart(index: p.index))
                }
            }
        case "content_block_delta":
            if let p = try? JSONDecoder().decode(ContentBlockDeltaEvent.self, from: payload) {
                if p.delta.type == "text_delta", let text = p.delta.text {
                    onEvent(.textDelta(index: p.index, text: text))
                } else if p.delta.type == "input_json_delta", let json = p.delta.partial_json {
                    onEvent(.toolInputDelta(index: p.index, partialJSON: json))
                } else if p.delta.type == "compaction_delta", let content = p.delta.content {
                    onEvent(.compactionDelta(index: p.index, content: content))
                }
            }
        case "content_block_stop":
            if let p = try? JSONDecoder().decode(ContentBlockStopEvent.self, from: payload) {
                onEvent(.blockStop(index: p.index))
            }
        case "message_delta":
            if let p = try? JSONDecoder().decode(MessageDeltaEvent.self, from: payload) {
                if let reason = p.delta.stop_reason {
                    onEvent(.messageStop(stopReason: reason))
                }
            }
        default: break
        }
    }
}

// MARK: - Events the view model listens for

enum StreamEvent {
    case textStart(index: Int)
    case textDelta(index: Int, text: String)
    case toolUseStart(index: Int, id: String, name: String)
    case toolInputDelta(index: Int, partialJSON: String)
    case compactionStart(index: Int)
    case compactionDelta(index: Int, content: String)
    case blockStop(index: Int)
    case messageStop(stopReason: String)
    case statusMessage(String)  // transient status (e.g. "retrying…")
}

// MARK: - Request

private struct RequestBody: Encodable {
    let model: String
    let maxTokens: Int
    let stream: Bool
    let system: [SystemBlock]
    let messages: [ChatMessage]
    let tools: [ToolDef]
    let contextManagement: ContextManagement?
    enum CodingKeys: String, CodingKey {
        case model, stream, system, messages, tools
        case maxTokens = "max_tokens"
        case contextManagement = "context_management"
    }
}

// MARK: - Server-side compaction (context management)

struct ContextManagement: Encodable {
    let edits: [CompactEdit]
}

struct CompactEdit: Encodable {
    let type: String           // "compact_20260112"
    let trigger: CompactTrigger
}

struct CompactTrigger: Encodable {
    let type: String           // "input_tokens"
    let value: Int             // token threshold
}

struct SystemBlock: Encodable {
    let type: String
    let text: String
}

// MARK: - SSE event payload structs

private struct ContentBlockStartEvent: Decodable {
    let index: Int
    let content_block: BlockInfo
    struct BlockInfo: Decodable {
        let type: String
        let id: String?
        let name: String?
    }
}
private struct ContentBlockDeltaEvent: Decodable {
    let index: Int
    let delta: Delta
    struct Delta: Decodable {
        let type: String
        let text: String?
        let partial_json: String?
        let content: String?
    }
}
private struct ContentBlockStopEvent: Decodable {
    let index: Int
}
private struct MessageDeltaEvent: Decodable {
    let delta: Delta
    struct Delta: Decodable { let stop_reason: String? }
}

// MARK: - Tool definitions (unchanged)

struct ToolDef: Encodable {
    let name: String
    let description: String
    let inputSchema: Schema
    enum CodingKeys: String, CodingKey {
        case name, description
        case inputSchema = "input_schema"
    }
}
struct Schema: Encodable {
    let type = "object"
    let properties: [String: AnyEncodable]
    let required: [String]

    init(properties: [String: Prop], required: [String]) {
        self.properties = properties.mapValues { AnyEncodable($0) }
        self.required = required
    }

    init(rawProperties: [String: AnyEncodable], required: [String]) {
        self.properties = rawProperties
        self.required = required
    }
}
struct Prop: Encodable {
    let type: String
    let description: String

    init(description: String) {
        self.type = "string"
        self.description = description
    }
    init(type: String, description: String) {
        self.type = type
        self.description = description
    }
}
struct ArrayProp: Encodable {
    let type = "array"
    let description: String
    let items: Prop
}
/// Type-erased Encodable wrapper
struct AnyEncodable: Encodable {
    private let _encode: (Encoder) throws -> Void
    init<T: Encodable>(_ value: T) {
        _encode = { try value.encode(to: $0) }
    }
    func encode(to encoder: Encoder) throws { try _encode(encoder) }
}

enum FileToolDefinitions {
    static let all: [ToolDef] = [
        ToolDef(name: "read_file",
                description: "Read the text contents of a file.",
                inputSchema: Schema(properties: ["path": Prop(description: "Absolute path")], required: ["path"])),
        ToolDef(name: "write_file",
                description: "Write content to a file (user must approve).",
                inputSchema: Schema(properties: ["path": Prop(description: "Absolute path"),
                                                 "content": Prop(description: "Content to write")],
                                    required: ["path", "content"])),
        ToolDef(name: "list_directory",
                description: "List contents of a directory.",
                inputSchema: Schema(properties: ["path": Prop(description: "Absolute path")], required: ["path"])),
        ToolDef(name: "search_files",
                description: "Search files by name pattern.",
                inputSchema: Schema(properties: ["directory": Prop(description: "Root directory"),
                                                 "pattern": Prop(description: "Filename substring")],
                                    required: ["directory", "pattern"])),
        ToolDef(name: "get_file_info",
                description: "Get file metadata.",
                inputSchema: Schema(properties: ["path": Prop(description: "Absolute path")], required: ["path"])),
        ToolDef(name: "bash_exec",
                description: "Execute a shell command and return stdout/stderr. Use for any command-line operation.",
                inputSchema: Schema(properties: ["command": Prop(description: "Shell command to execute")],
                                    required: ["command"])),
        ToolDef(name: "grep_search",
                description: "Search file contents for a text pattern. Returns matching lines with file paths and line numbers.",
                inputSchema: Schema(properties: ["pattern": Prop(description: "Text pattern to search for (case-insensitive)"),
                                                 "directory": Prop(description: "Root directory to search in")],
                                    required: ["pattern", "directory"])),
        ToolDef(name: "head_file",
                description: "Read the first N lines of a file with line numbers.",
                inputSchema: Schema(properties: ["path": Prop(description: "Absolute path"),
                                                 "lines": Prop(description: "Number of lines to read (default 50)")],
                                    required: ["path"])),
        ToolDef(name: "tail_file",
                description: "Read the last N lines of a file with line numbers.",
                inputSchema: Schema(properties: ["path": Prop(description: "Absolute path"),
                                                 "lines": Prop(description: "Number of lines to read (default 50)")],
                                    required: ["path"])),
        ToolDef(name: "process_list",
                description: "List all running processes with PID and name.",
                inputSchema: Schema(properties: [:], required: [])),
        ToolDef(name: "device_info",
                description: "Get device information: model, iOS version, RAM, disk space, battery, sandbox status.",
                inputSchema: Schema(properties: [:], required: [])),
        ToolDef(name: "open_url",
                description: "Open a URL on the device (launches Safari, App Store links, URL schemes, etc.).",
                inputSchema: Schema(properties: ["url": Prop(description: "URL to open")],
                                    required: ["url"])),
        ToolDef(name: "remote_call",
                description: "Call a C function in another running process via Mach task ports (requires sandbox escape). Attaches to target process, calls the named function with up to 8 uint64 arguments, returns the result. Use for SpringBoard tweaks, process inspection, etc.",
                inputSchema: Schema(rawProperties: [
                    "process": AnyEncodable(Prop(description: "Target process name (e.g. 'SpringBoard', 'launchd')")),
                    "function": AnyEncodable(Prop(description: "C function name to call in the remote process")),
                    "args": AnyEncodable(ArrayProp(
                        description: "Up to 8 uint64 arguments. Pass numbers or hex strings like '0x1234'.",
                        items: Prop(description: "Argument value")))
                ], required: ["process", "function"])),
        ToolDef(name: "sqlite_query",
                description: "Run a read-only SQL query against any SQLite database on the device. Returns results as tab-separated text with column headers. Use for reading SMS (sms.db), call history, Safari history, app databases, etc.",
                inputSchema: Schema(properties: [
                    "database": Prop(description: "Absolute path to the SQLite database file"),
                    "query": Prop(description: "SQL SELECT query to execute (read-only, no DROP/DELETE/UPDATE/INSERT)")
                ], required: ["database", "query"])),
        ToolDef(name: "installed_apps",
                description: "List all installed applications on the device with bundle ID, version, size, and install path. Requires sandbox escape.",
                inputSchema: Schema(properties: [:], required: [])),
        ToolDef(name: "read_plist",
                description: "Read and decode a binary or XML property list (.plist) file into human-readable text. Use for reading app preferences, system configuration, entitlements, etc.",
                inputSchema: Schema(properties: [
                    "path": Prop(description: "Absolute path to the .plist file")
                ], required: ["path"])),
        ToolDef(name: "memory_dump",
                description: "Read and hex-dump memory from any running process. Attaches via Mach task ports, reads raw bytes at a given address, and displays a formatted hex+ASCII dump. Use for inspecting process memory, finding strings, reverse engineering. Requires sandbox escape.",
                inputSchema: Schema(rawProperties: [
                    "process": AnyEncodable(Prop(description: "Target process name (e.g. 'SpringBoard', 'MobileSafari')")),
                    "address": AnyEncodable(Prop(description: "Memory address to read from. Hex (0x1a2b3c) or decimal.")),
                    "size": AnyEncodable(Prop(type: "integer", description: "Number of bytes to read (16–4096, default 256)"))
                ], required: ["process", "address"])),
        ToolDef(name: "app_control",
                description: "Control running apps: freeze (SIGSTOP — pauses the process entirely), unfreeze (SIGCONT — resumes it), kill (SIGTERM), or launch an app by bundle ID. Freeze is instant and the app stays frozen until you unfreeze it.",
                inputSchema: Schema(properties: [
                    "action": Prop(description: "One of: freeze, unfreeze, kill, launch"),
                    "target": Prop(description: "Process name or PID (for freeze/unfreeze/kill), or bundle ID (for launch)")
                ], required: ["action", "target"])),
        ToolDef(name: "copy_move_file",
                description: "Copy or move a file. Works with binary files (plists, databases, images, etc.) unlike write_file which is text-only. Use this to restore .claudebackup files, duplicate files, or relocate them. Shell commands like cp/mv may not be available — always use this tool instead.",
                inputSchema: Schema(properties: [
                    "source": Prop(description: "Absolute path of the source file"),
                    "destination": Prop(description: "Absolute path of the destination"),
                    "move": Prop(description: "Set to 'true' to move instead of copy (default: copy)")
                ], required: ["source", "destination"])),
    ]
}

// MARK: - JSON values (needed by Message model)

enum AnyJSON: Codable {
    case string(String), number(Double), bool(Bool), array([AnyJSON]), object([String: AnyJSON]), null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil()                                     { self = .null }
        else if let b = try? c.decode(Bool.self)             { self = .bool(b) }
        else if let n = try? c.decode(Double.self)           { self = .number(n) }
        else if let s = try? c.decode(String.self)           { self = .string(s) }
        else if let a = try? c.decode([AnyJSON].self)        { self = .array(a) }
        else if let o = try? c.decode([String: AnyJSON].self){ self = .object(o) }
        else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "?")) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null:          try c.encodeNil()
        case .bool(let b):   try c.encode(b)
        case .number(let n): try c.encode(n)
        case .string(let s): try c.encode(s)
        case .array(let a):  try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
    var string: String? { if case .string(let s) = self { return s } else { return nil } }
    var intValue: Int? { if case .number(let n) = self { return Int(n) } else { return nil } }
    var uint64Value: UInt64? { if case .number(let n) = self { return UInt64(n) } else { return nil } }
    var arrayValue: [AnyJSON] { if case .array(let a) = self { return a } else { return [] } }
}

// MARK: - Errors

enum APIError: LocalizedError {
    case invalidResponse, serverError(String), cancelled, authExpired
    case rateLimited(retryAfterSeconds: Double)
    case creditsRequired(String)  // model display name

    var errorDescription: String? {
        switch self {
        case .invalidResponse:          return "Invalid response"
        case .serverError(let m):       return m
        case .cancelled:                return "Cancelled"
        case .authExpired:              return "Session expired — refreshing…"
        case .rateLimited:              return "Rate limited — please wait"
        case .creditsRequired(let m):   return "\(m) requires usage credits. Switch to a different model or purchase credits at claude.ai."
        }
    }
}

// MARK: - JSON field extraction

extension AnthropicClient {
    static func extractField(from json: String, field: String) -> String? {
        // Simple extraction without full JSON parsing
        guard let range = json.range(of: "\"\(field)\"") else { return nil }
        let after = json[range.upperBound...]
        guard let colonIdx = after.firstIndex(of: ":") else { return nil }
        let valueArea = after[after.index(after: colonIdx)...]
            .trimmingCharacters(in: .whitespaces)
        if valueArea.hasPrefix("\"") {
            let inner = valueArea.dropFirst()
            if let end = inner.firstIndex(of: "\"") {
                return String(inner[..<end])
            }
        }
        return nil
    }
}
