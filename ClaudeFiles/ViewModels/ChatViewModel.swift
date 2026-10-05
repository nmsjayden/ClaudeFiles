import Foundation
import SwiftUI

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var displayMessages: [DisplayMessage] = []
    @Published var inputText:       String = ""
    @Published var isSending:       Bool   = false
    @Published var error:           String?
    @Published var pendingWrite:    PendingWrite?

    private var history:   [ChatMessage]      = []
    private let api      = AnthropicClient()
    private let executor = FileToolsExecutor()
    private let authMgr  = AuthManager.shared

    private let system = """
    You are Claude, a helpful AI assistant running inside a custom iOS app with full filesystem \
    read/write access via the DarkSword kernel exploit. You have five file tools: read_file, \
    write_file, list_directory, search_files, get_file_info. Use them freely to help the user. \
    The user is debugging a black screen on the back camera in the iOS Camera app (works in \
    Roblox and other apps). Key paths: \
    /var/mobile/Library/Preferences/com.apple.camera.plist, \
    /var/mobile/Library/Logs/CrashReporter/, /tmp/. \
    Always back up files before writing. Confirm before any write.
    """

    // MARK: - Send

    func send() {
        let text = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !isSending else { return }
        inputText = ""
        isSending = true
        error = nil

        displayMessages.append(DisplayMessage(role: .user, text: text))
        history.append(ChatMessage(role: .user, content: .text(text)))

        Task { await runTurn() }
    }

    // MARK: - Agentic loop

    private func runTurn() async {
        defer { isSending = false }

        guard let token = await authMgr.accessToken() else {
            error = "Not logged in"; return
        }

        do {
            var response = try await api.send(messages: history, system: system, accessToken: token)

            while response.stopReason == "tool_use" {
                // Build assistant blocks for history
                let blocks: [APIBlock] = response.content.map { block in
                    switch block {
                    case .text(let t):
                        return APIBlock(type: "text", text: t, id: nil, name: nil, input: nil)
                    case .toolUse(let tu):
                        return APIBlock(type: "tool_use", text: nil, id: tu.id, name: tu.name, input: tu.input)
                    case .unknown:
                        return APIBlock(type: "text", text: "", id: nil, name: nil, input: nil)
                    }
                }
                history.append(ChatMessage(role: .assistant, content: .blocks(blocks)))

                // Show text portion if any
                let txt = response.text
                if !txt.isEmpty {
                    displayMessages.append(DisplayMessage(role: .assistant, text: txt))
                }

                // Execute tools
                for tu in response.toolUses {
                    let result = await executeTool(tu)
                    history.append(ChatMessage(role: .user,
                                               content: .toolResult(toolUseId: tu.id, result: result)))
                }

                response = try await api.send(messages: history, system: system, accessToken: token)
            }

            // Final reply
            let finalText = response.text
            if !finalText.isEmpty {
                displayMessages.append(DisplayMessage(role: .assistant, text: finalText))
                history.append(ChatMessage(role: .assistant, content: .text(finalText)))
            }

        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: - Tool execution

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

    func clearHistory() {
        displayMessages = []
        history = []
    }
}

// MARK: - PendingWrite

struct PendingWrite: Identifiable {
    let id       = UUID()
    let path:      String
    let preview:   String
    let onApprove: () -> Void
    let onDeny:    () -> Void
}
