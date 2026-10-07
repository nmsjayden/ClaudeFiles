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
        case .toolResults(let results):
            let blocks = results.map { ToolResultBlock(type: "tool_result", toolUseId: $0.toolUseId, content: $0.result) }
            try c.encode(blocks, forKey: .content)
        case .textWithImages(let text, let images):
            var blocks: [ImageAPIContent] = []
            for img in images {
                blocks.append(.image(ImageContentBlock(
                    source: ImageSource(mediaType: img.mimeType, data: img.base64Data)
                )))
            }
            if !text.isEmpty {
                blocks.append(.text(TextContentBlock(text: text)))
            }
            try c.encode(blocks, forKey: .content)
        }
    }
}

enum MessageContent {
    case text(String)
    case blocks([APIBlock])
    case toolResult(toolUseId: String, result: String)
    case toolResults([(toolUseId: String, result: String)])
    case textWithImages(String, [StoredAttachment])
}

// MARK: - Image content blocks for API

enum ImageAPIContent: Encodable {
    case image(ImageContentBlock)
    case text(TextContentBlock)

    func encode(to encoder: Encoder) throws {
        switch self {
        case .image(let block): try block.encode(to: encoder)
        case .text(let block):  try block.encode(to: encoder)
        }
    }
}

struct ImageContentBlock: Encodable {
    let type = "image"
    let source: ImageSource
}

struct ImageSource: Encodable {
    let type = "base64"
    let mediaType: String
    let data: String

    enum CodingKeys: String, CodingKey {
        case type
        case mediaType = "media_type"
        case data
    }
}

struct TextContentBlock: Encodable {
    let type = "text"
    let text: String
}

// MARK: - Stored attachment (persisted on disk)

struct StoredAttachment: Codable, Equatable {
    let mimeType:   String   // "image/jpeg", "image/png", "image/gif", "image/webp"
    let base64Data: String   // base64-encoded image data
    let fileName:   String?  // optional display name

    /// Decode the base64 data back into a UIKit-compatible Data object
    var imageData: Data? { Data(base64Encoded: base64Data) }

    /// Approximate size in bytes of the base64-encoded data
    var estimatedBytes: Int { base64Data.count * 3 / 4 }
}

// Encodable block for API messages — omits nil fields explicitly
struct APIBlock: Encodable {
    let type:  String
    let text:  String?
    let id:    String?
    let name:  String?
    let input: [String: AnyJSON]?

    enum CodingKeys: String, CodingKey { case type, text, id, name, input, content }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(type, forKey: .type)
        // Compaction blocks use "content" key instead of "text"
        if type == "compaction" {
            if let text = text { try c.encode(text, forKey: .content) }
        } else {
            if let text = text { try c.encode(text, forKey: .text) }
        }
        if let id    = id    { try c.encode(id,    forKey: .id) }
        if let name  = name  { try c.encode(name,  forKey: .name) }
        if let input = input { try c.encode(input, forKey: .input) }
    }
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
    var toolCalls: [ToolCallInfo] = []
    var isLoading: Bool = false
    var attachments: [StoredAttachment] = []
}
