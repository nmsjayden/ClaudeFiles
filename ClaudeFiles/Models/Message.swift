import Foundation

// MARK: - Chat message (sent to API)

struct ChatMessage: Encodable, Identifiable {
    let id   = UUID()
    let role : Role
    let content: MessageContent

    enum Role: String, Encodable { case user, assistant }

    enum CodingKeys: String, CodingKey { case role, content }
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(role, forKey: .role)
        switch content {
        case .text(let t):
            try c.encode(t, forKey: .content)
        case .blocks(let b):
            try c.encode(b, forKey: .content)
        case .toolResult(let id, let result):
            let block = ToolResultBlock(type: "tool_result", toolUseId: id, content: result)
            try c.encode([block], forKey: .content)
        }
    }
}

enum MessageContent {
    case text(String)
    case blocks([APIBlock])
    case toolResult(toolUseId: String, result: String)
}

// Encodable block for API messages
struct APIBlock: Encodable {
    let type:  String
    let text:  String?
    let id:    String?
    let name:  String?
    let input: [String: AnyJSON]?
}

struct ToolResultBlock: Encodable {
    let type:      String
    let toolUseId: String
    let content:   String
    enum CodingKeys: String, CodingKey {
        case type, content
        case toolUseId = "tool_use_id"
    }
}

// MARK: - Display message (shown in UI)

struct DisplayMessage: Identifiable {
    let id       = UUID()
    let role     : ChatMessage.Role
    var text     : String
    var isLoading: Bool = false
}
