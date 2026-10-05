import Foundation
import SwiftUI

// A saved conversation
struct Conversation: Identifiable, Codable {
    let id:          UUID
    var title:       String
    var createdAt:   Date
    var updatedAt:   Date
    var messages:    [StoredMessage]

    init(id: UUID = UUID(), title: String = "New chat") {
        self.id        = id
        self.title     = title
        self.createdAt = Date()
        self.updatedAt = Date()
        self.messages  = []
    }
}

// A message stored on disk. Keep it simple — role + text + optional tool metadata.
struct StoredMessage: Codable {
    let role:  String   // "user" | "assistant"
    let text:  String
    // Optional raw API blocks (for assistant tool-use turns)
    var apiBlocks: [StoredBlock]?
    // Optional tool result (when role == user carrying a tool result)
    var toolUseId:     String?
    var toolResult:    String?
}

struct StoredBlock: Codable {
    let type:  String
    let text:  String?
    let id:    String?
    let name:  String?
    let input: [String: AnyJSON]?
}

@MainActor
final class ConversationStore: ObservableObject {
    @Published var conversations: [Conversation] = []
    @Published var selectedId:    UUID?

    private let fileURL: URL

    init() {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = dir.appendingPathComponent("conversations.json")
        load()
        if conversations.isEmpty {
            let c = Conversation(title: "New chat")
            conversations = [c]
            selectedId = c.id
            save()
        } else {
            selectedId = conversations.first?.id
        }
    }

    var selected: Conversation? {
        get { conversations.first(where: { $0.id == selectedId }) }
    }

    func newConversation() {
        let c = Conversation()
        conversations.insert(c, at: 0)
        selectedId = c.id
        save()
    }

    func delete(_ id: UUID) {
        conversations.removeAll { $0.id == id }
        if selectedId == id { selectedId = conversations.first?.id }
        if conversations.isEmpty {
            let c = Conversation()
            conversations = [c]
            selectedId = c.id
        }
        save()
    }

    func rename(_ id: UUID, to title: String) {
        guard let i = conversations.firstIndex(where: { $0.id == id }) else { return }
        conversations[i].title = title
        save()
    }

    func update(_ conversation: Conversation) {
        guard let i = conversations.firstIndex(where: { $0.id == conversation.id }) else { return }
        var c = conversation
        c.updatedAt = Date()
        conversations[i] = c
        // Keep most-recent on top
        conversations.sort { $0.updatedAt > $1.updatedAt }
        save()
    }

    /// Mutate a specific conversation by id. Used during streaming so updates land
    /// on the right conversation even if the user has switched to a different one.
    @discardableResult
    func mutateById(_ id: UUID, _ change: (inout Conversation) -> Void) -> Bool {
        guard let i = conversations.firstIndex(where: { $0.id == id }) else { return false }
        var c = conversations[i]
        change(&c)
        c.updatedAt = Date()
        conversations[i] = c
        conversations.sort { $0.updatedAt > $1.updatedAt }
        save()
        return true
    }

    /// Append a single message to a specific conversation.
    func appendMessage(to id: UUID, _ message: StoredMessage) {
        mutateById(id) { $0.messages.append(message) }
    }

    // MARK: - Persistence

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([Conversation].self, from: data)
        else { return }
        conversations = decoded.sorted { $0.updatedAt > $1.updatedAt }
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(conversations) else { return }
        try? data.write(to: fileURL)
    }
}
