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
        let model = SettingsStore.shared.selectedModel

        var components = URLComponents(url: apiURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "beta", value: "true")]
        var req = URLRequest(url: components.url!)
        req.httpMethod = "POST"

        req.setValue("Bearer \(accessToken)",            forHTTPHeaderField: "Authorization")
        req.setValue("application/json",                 forHTTPHeaderField: "Content-Type")
        req.setValue("text/event-stream",                forHTTPHeaderField: "Accept")
        req.setValue("2023-06-01",                       forHTTPHeaderField: "anthropic-version")
        req.setValue("claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05",
                     forHTTPHeaderField: "anthropic-beta")
        req.setValue("true",                             forHTTPHeaderField: "anthropic-dangerous-direct-browser-access")
        req.setValue("claude-cli/2.1.92 (external, cli)", forHTTPHeaderField: "User-Agent")
        req.setValue("cli",                               forHTTPHeaderField: "x-app")
        req.setValue("js",                                forHTTPHeaderField: "x-stainless-lang")
        req.setValue("0.74.0",                            forHTTPHeaderField: "x-stainless-package-version")
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

        let body = RequestBody(model: model, maxTokens: 8192, stream: true,
                               system: systemBlocks, messages: messages,
                               tools: FileToolDefinitions.all)
        req.httpBody = try JSONEncoder().encode(body)

        let (bytes, response) = try await URLSession.shared.bytes(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }

        if http.statusCode != 200 {
            var buf = Data()
            for try await byte in bytes { buf.append(byte) }
            let raw = String(data: buf, encoding: .utf8) ?? "<non-utf8>"
            throw APIError.serverError("HTTP \(http.statusCode)\n\n\(raw.prefix(2000))")
        }

        // Parse SSE events
        var currentEvent = ""
        var currentData = ""

        for try await line in bytes.lines {
            if try Task.checkCancellation() == () {}
            if line.isEmpty {
                if !currentData.isEmpty {
                    processSSE(event: currentEvent, data: currentData, onEvent: onEvent)
                }
                currentEvent = ""
                currentData = ""
            } else if line.hasPrefix("event: ") {
                currentEvent = String(line.dropFirst(7))
            } else if line.hasPrefix("data: ") {
                currentData = String(line.dropFirst(6))
            }
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
                }
            }
        case "content_block_delta":
            if let p = try? JSONDecoder().decode(ContentBlockDeltaEvent.self, from: payload) {
                if p.delta.type == "text_delta", let text = p.delta.text {
                    onEvent(.textDelta(index: p.index, text: text))
                } else if p.delta.type == "input_json_delta", let json = p.delta.partial_json {
                    onEvent(.toolInputDelta(index: p.index, partialJSON: json))
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
    case blockStop(index: Int)
    case messageStop(stopReason: String)
}

// MARK: - Request

private struct RequestBody: Encodable {
    let model: String
    let maxTokens: Int
    let stream: Bool
    let system: [SystemBlock]
    let messages: [ChatMessage]
    let tools: [ToolDef]
    enum CodingKeys: String, CodingKey {
        case model, stream, system, messages, tools
        case maxTokens = "max_tokens"
    }
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
    let properties: [String: Prop]
    let required: [String]
}
struct Prop: Encodable {
    let type = "string"
    let description: String
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
}

// MARK: - Errors

enum APIError: LocalizedError {
    case invalidResponse, serverError(String), cancelled
    var errorDescription: String? {
        switch self {
        case .invalidResponse:   return "Invalid response"
        case .serverError(let m):return m
        case .cancelled:         return "Cancelled"
        }
    }
}
