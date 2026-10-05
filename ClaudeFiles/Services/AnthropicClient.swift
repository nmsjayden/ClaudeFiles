import Foundation

// MARK: - Client

final class AnthropicClient {
    private let apiURL    = URL(string: "https://api.anthropic.com/v1/messages")!
    private let model     = "claude-sonnet-4-5-20250929"

    func send(messages: [ChatMessage], system: String, accessToken: String) async throws -> APIResponse {
        var req = URLRequest(url: apiURL)
        req.httpMethod = "POST"
        req.setValue("Bearer \(accessToken)",  forHTTPHeaderField: "Authorization")
        req.setValue("application/json",        forHTTPHeaderField: "Content-Type")
        req.setValue("2023-06-01",              forHTTPHeaderField: "anthropic-version")
        // Match Claude Code CLI's full beta header stack
        req.setValue("oauth-2025-04-20,claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14",
                     forHTTPHeaderField: "anthropic-beta")
        req.setValue("claude-cli/1.0.60 (external, cli)", forHTTPHeaderField: "User-Agent")
        req.setValue("cli",                               forHTTPHeaderField: "x-app")

        // Prepend Claude Code's required system identifier
        let claudeCodeSystem = "You are Claude Code, Anthropic's official CLI for Claude.\n\n" + system

        let body = RequestBody(model: model, maxTokens: 4096, system: claudeCodeSystem,
                               messages: messages, tools: FileToolDefinitions.all)
        req.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw APIError.invalidResponse }
        if http.statusCode != 200 {
            let msg = (try? JSONDecoder().decode(APIErrorBody.self, from: data))?.error.message
                      ?? "HTTP \(http.statusCode)"
            throw APIError.serverError(msg)
        }
        return try JSONDecoder().decode(APIResponse.self, from: data)
    }
}

// MARK: - Request

private struct RequestBody: Encodable {
    let model: String
    let maxTokens: Int
    let system: String
    let messages: [ChatMessage]
    let tools: [ToolDef]
    enum CodingKeys: String, CodingKey {
        case model, system, messages, tools
        case maxTokens = "max_tokens"
    }
}

// MARK: - Response

struct APIResponse: Decodable {
    let stopReason: String?
    let content: [ContentBlock]
    enum CodingKeys: String, CodingKey {
        case content
        case stopReason = "stop_reason"
    }

    var text: String {
        content.compactMap { if case .text(let t) = $0 { return t } else { return nil } }.joined()
    }
    var toolUses: [ToolUseBlock] {
        content.compactMap { if case .toolUse(let t) = $0 { return t } else { return nil } }
    }
}

enum ContentBlock: Decodable {
    case text(String)
    case toolUse(ToolUseBlock)
    case unknown

    enum CK: String, CodingKey { case type, text }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CK.self)
        switch try c.decode(String.self, forKey: .type) {
        case "text":     self = .text(try c.decode(String.self, forKey: .text))
        case "tool_use": self = .toolUse(try ToolUseBlock(from: decoder))
        default:         self = .unknown
        }
    }
}

struct ToolUseBlock: Decodable {
    let id:    String
    let name:  String
    let input: [String: AnyJSON]
}

// MARK: - Tool definitions

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

// MARK: - AnyJSON (replaces JSONValue)

enum AnyJSON: Codable {
    case string(String), number(Double), bool(Bool), array([AnyJSON]), object([String: AnyJSON]), null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil()                                    { self = .null }
        else if let b = try? c.decode(Bool.self)            { self = .bool(b) }
        else if let n = try? c.decode(Double.self)          { self = .number(n) }
        else if let s = try? c.decode(String.self)          { self = .string(s) }
        else if let a = try? c.decode([AnyJSON].self)       { self = .array(a) }
        else if let o = try? c.decode([String: AnyJSON].self){ self = .object(o) }
        else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Unknown")) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null:         try c.encodeNil()
        case .bool(let b):  try c.encode(b)
        case .number(let n):try c.encode(n)
        case .string(let s):try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o):try c.encode(o)
        }
    }
    var string: String? { if case .string(let s) = self { return s } else { return nil } }
}

// MARK: - Errors

enum APIError: LocalizedError {
    case invalidResponse, serverError(String)
    var errorDescription: String? {
        switch self {
        case .invalidResponse:   return "Invalid response"
        case .serverError(let m):return m
        }
    }
}
struct APIErrorBody: Decodable {
    let error: Msg
    struct Msg: Decodable { let message: String }
}
