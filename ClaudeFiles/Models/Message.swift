import Foundation

// MARK: - Message

struct Message: Identifiable {
    let id = UUID()
    let role: Role
    var content: MessageContent
    var toolCalls: [ToolCall] = []      // populated when assistant requests tool use
    var isLoading: Bool = false

    enum Role: String { case user, assistant }
}

enum MessageContent {
    case text(String)
    case toolResult(toolUseId: String, result: String)
    case assistantBlocks([ContentBlock])   // mirrors API response blocks
}

// MARK: - Tool call (pending / completed)

struct ToolCall: Identifiable {
    let id = UUID()
    let toolUseId: String
    let name:      String
    let input:     [String: JSONValue]
    var state:     State = .pending
    var result:    String = ""

    enum State { case pending, needsApproval, running, done, denied }
}

// MARK: - Display helper

extension Message {
    var displayText: String {
        switch content {
        case .text(let t):                        return t
        case .toolResult(_, let r):               return r
        case .assistantBlocks(let blocks):
            return blocks.compactMap {
                if case .text(let t) = $0 { return t } else { return nil }
            }.joined()
        }
    }
}
