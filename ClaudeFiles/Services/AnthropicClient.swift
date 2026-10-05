import Foundation

final class AnthropicClient {

    private let apiURL = URL(string: "https://api.anthropic.com/v1/messages")!
    private let model  = "claude-sonnet-4-6"
    private let authManager: AuthManager

    init(authManager: AuthManager = .shared) {
        self.authManager = authManager
    }

    // MARK: - Public

    /// Send a conversation turn and return the response.
    /// If Claude wants to call a tool the caller gets back a `.toolUse` result.
    func send(messages: [Message], system: String) async throws -> APIResponse {
        guard let token = await authManager.accessToken() else {
            throw APIError.notAuthenticated
        }

        var req = URLRequest(url: apiURL)
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)",    forHTTPHeaderField: "Authorization")
        req.setValue("application/json",   forHTTPHeaderField: "Content-Type")
        req.setValue("2023-06-01",         forHTTPHeaderField: "anthropic-version")
        req.setValue("oauth-2025-04-20",   forHTTPHeaderField: "anthropic-beta")

        let body = RequestBody(
            model:      model,
            maxTokens:  4096,
            system:     system,
            messages:   messages.map { $0.toAPI() },
            tools:      FileTools.definitions
        )
        req.httpBody = try JSONEncoder().encode(body)

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw APIError.invalidResponse }

        if http.statusCode != 200 {
            let msg = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error.message ?? "HTTP \(http.statusCode)"
            throw APIError.serverError(msg)
        }

        return try JSONDecoder().decode(APIResponse.self, from: data)
    }
}

// MARK: - Request types

private struct RequestBody: Encodable {
    let model:     String
    let maxTokens: Int
    let system:    String
    let messages:  [[String: JSONValue]]
    let tools:     [ToolDefinition]

    enum CodingKeys: String, CodingKey {
        case model, system, messages, tools
        case maxTokens = "max_tokens"
    }
}

// MARK: - Response types

struct APIResponse: Decodable {
    let id:          String
    let stopReason:  String?
    let content:     [ContentBlock]

    enum CodingKeys: String, CodingKey {
        case id, content
        case stopReason = "stop_reason"
    }

    var textContent: String {
        content.compactMap { if case .text(let t) = $0 { return t } else { return nil } }.joined()
    }

    var toolUses: [ToolUseBlock] {
        content.compactMap { if case .toolUse(let t) = $0 { return t } else { return nil } }
    }
}

enum ContentBlock: Decodable {
    case text(String)
    case toolUse(ToolUseBlock)
    case other

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let type = try c.decode(String.self, forKey: .type)
        switch type {
        case "text":     self = .text(try c.decode(String.self, forKey: .text))
        case "tool_use": self = .toolUse(try ToolUseBlock(from: decoder))
        default:         self = .other
        }
    }
    enum CodingKeys: String, CodingKey { case type, text }
}

struct ToolUseBlock: Decodable {
    let id:    String
    let name:  String
    let input: [String: JSONValue]
}

struct ToolDefinition: Encodable {
    let name:        String
    let description: String
    let inputSchema: JSONSchema

    enum CodingKeys: String, CodingKey {
        case name, description
        case inputSchema = "input_schema"
    }
}

struct JSONSchema: Encodable {
    let type:       String
    let properties: [String: PropertySchema]
    let required:   [String]
}

struct PropertySchema: Encodable {
    let type:        String
    let description: String
}

struct ErrorBody: Decodable {
    let error: ErrorDetail
    struct ErrorDetail: Decodable { let message: String }
}

enum APIError: LocalizedError {
    case notAuthenticated
    case invalidResponse
    case serverError(String)

    var errorDescription: String? {
        switch self {
        case .notAuthenticated:   return "Not logged in"
        case .invalidResponse:    return "Invalid server response"
        case .serverError(let m): return m
        }
    }
}

// MARK: - Flexible JSON value type

enum JSONValue: Codable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil()                              { self = .null }
        else if let b = try? c.decode(Bool.self)      { self = .bool(b) }
        else if let i = try? c.decode(Int.self)       { self = .int(i) }
        else if let d = try? c.decode(Double.self)    { self = .double(d) }
        else if let s = try? c.decode(String.self)    { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else if let o = try? c.decode([String: JSONValue].self) { self = .object(o) }
        else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unknown JSON") }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null:         try c.encodeNil()
        case .bool(let b):  try c.encode(b)
        case .int(let i):   try c.encode(i)
        case .double(let d):try c.encode(d)
        case .string(let s):try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o):try c.encode(o)
        }
    }

    var stringValue: String? { if case .string(let s) = self { return s } else { return nil } }
}

// MARK: - Message conversion helper

extension Message {
    func toAPI() -> [String: JSONValue] {
        var d: [String: JSONValue] = ["role": .string(role.rawValue)]
        switch content {
        case .text(let t):
            d["content"] = .string(t)
        case .toolResult(let id, let result):
            d["content"] = .array([.object([
                "type":        .string("tool_result"),
                "tool_use_id": .string(id),
                "content":     .string(result),
            ])])
        case .assistantBlocks(let blocks):
            d["content"] = .array(blocks.map { block -> JSONValue in
                switch block {
                case .text(let t):
                    return .object(["type": .string("text"), "text": .string(t)])
                case .toolUse(let tu):
                    return .object([
                        "type":  .string("tool_use"),
                        "id":    .string(tu.id),
                        "name":  .string(tu.name),
                        "input": .object(tu.input),
                    ])
                case .other:
                    return .object(["type": .string("text"), "text": .string("")])
                }
            })
        }
        return d
    }
}
