import Foundation
import SwiftUI

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var inputText:    String = ""
    @Published var isSending:    Bool   = false
    @Published var error:        String?
    @Published var pendingWrite: PendingWrite?

    private let api      = AnthropicClient()
    private let executor = FileToolsExecutor()
    private let authMgr  = AuthManager.shared

    unowned let store: ConversationStore

    init(store: ConversationStore) {
        self.store = store
    }

    private let systemPrompt = """
    You are a helpful AI assistant running inside a custom iOS app with full filesystem \
    read/write access via the DarkSword kernel exploit. You have five file tools: read_file, \
    write_file, list_directory, search_files, get_file_info. Use them freely to help the user. \
    The user is debugging a black screen on the back camera in the iOS Camera app (works in \
    Roblox and other apps). Key paths: \
    /var/mobile/Library/Preferences/com.apple.camera.plist, \
    /var/mobile/Library/Logs/CrashReporter/, /tmp/. \
    Always back up files before writing. Confirm before any write.
    """

    var displayMessages: [DisplayMessage] {
        guard let c = store.selected else { return [] }
        return c.messages.compactMap { m in
            if m.toolUseId != nil { return nil }
            guard !m.text.isEmpty else { return nil }
            let role: ChatMessage.Role = (m.role == "user") ? .user : .assistant
            return DisplayMessage(role: role, text: m.text)
        }
    }

    func send() {
        let text = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !isSending else { return }
        guard var conv = store.selected else { return }
        inputText = ""
        isSending = true
        error = nil

        conv.messages.append(StoredMessage(role: "user", text: text,
                                           apiBlocks: nil, toolUseId: nil, toolResult: nil))
        if conv.title == "New chat" {
            conv.title = String(text.prefix(40))
        }
        store.update(conv)

        Task { await runTurn() }
    }

    private func runTurn() async {
        defer { isSending = false }

        guard let token = await authMgr.accessToken() else {
            error = "Not logged in"; return
        }

        do {
            var history = buildAPIHistory()
            var response = try await api.send(messages: history, system: systemPrompt, accessToken: token)

            while response.stopReason == "tool_use" {
                let apiBlocks: [StoredBlock] = response.content.compactMap { block -> StoredBlock? in
                    switch block {
                    case .text(let t):
                        return StoredBlock(type: "text", text: t, id: nil, name: nil, input: nil)
                    case .toolUse(let tu):
                        return StoredBlock(type: "tool_use", text: nil, id: tu.id, name: tu.name, input: tu.input)
                    case .unknown: return nil
                    }
                }
                let visibleText = response.text
                if var conv = store.selected {
                    conv.messages.append(StoredMessage(role: "assistant", text: visibleText,
                                                       apiBlocks: apiBlocks,
                                                       toolUseId: nil, toolResult: nil))
                    store.update(conv)
                }

                for tu in response.toolUses {
                    let result = await executeTool(tu)
                    if var conv = store.selected {
                        conv.messages.append(StoredMessage(role: "user", text: "",
                                                           apiBlocks: nil,
                                                           toolUseId: tu.id, toolResult: result))
                        store.update(conv)
                    }
                }

                history = buildAPIHistory()
                response = try await api.send(messages: history, system: systemPrompt, accessToken: token)
            }

            let finalText = response.text
            if !finalText.isEmpty, var conv = store.selected {
                conv.messages.append(StoredMessage(role: "assistant", text: finalText,
                                                   apiBlocks: nil, toolUseId: nil, toolResult: nil))
                store.update(conv)
            }

        } catch {
            self.error = error.localizedDescription
        }
    }

    private func buildAPIHistory() -> [ChatMessage] {
        guard let c = store.selected else { return [] }
        return c.messages.compactMap { m -> ChatMessage? in
            if let toolId = m.toolUseId, let result = m.toolResult {
                return ChatMessage(role: .user, content: .toolResult(toolUseId: toolId, result: result))
            }
            if m.role == "user" {
                return ChatMessage(role: .user, content: .text(m.text))
            }
            if let blocks = m.apiBlocks, !blocks.isEmpty {
                let apiBlocks = blocks.map { b in
                    APIBlock(type: b.type, text: b.text, id: b.id, name: b.name, input: b.input)
                }
                return ChatMessage(role: .assistant, content: .blocks(apiBlocks))
            }
            return ChatMessage(role: .assistant, content: .text(m.text))
        }
    }

    private func executeTool(_ tu: ToolUseBlock) async -> String {
        if tu.name == "write_file",
           let path    = tu.input["path"]?.string,
           let content = tu.input["content"]?.string {
            return await requestWriteApproval(path: path, content: content)
        }
        return await executor.execute(name: tu.name, input: tu.input)
    }

    private func requestWriteApproval(path: String, content: String) async -> String {
        await withCheckedContinuation { cont in
            pendingWrite = PendingWrite(
                path:    path,
                preview: String(content.prefix(600)),
                onApprove: { [weak self] in
                    guard let self else { return }
                    Task { @MainActor in
                        let r = await self.executor.execute(
                            name: "write_file",
                            input: ["path": .string(path), "content": .string(content)]
                        )
                        self.pendingWrite = nil
                        cont.resume(returning: r)
                    }
                },
                onDeny: { [weak self] in
                    self?.pendingWrite = nil
                    cont.resume(returning: "User denied write to \(path)")
                }
            )
        }
    }
}

struct PendingWrite: Identifiable {
    let id       = UUID()
    let path:      String
    let preview:   String
    let onApprove: () -> Void
    let onDeny:    () -> Void
}
