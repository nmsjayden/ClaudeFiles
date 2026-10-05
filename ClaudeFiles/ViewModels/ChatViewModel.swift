import Foundation
import SwiftUI

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var messages: [Message] = []
    @Published var inputText: String = ""
    @Published var isSending: Bool = false
    @Published var error: String?

    // Write-approval state
    @Published var pendingWrite: PendingWrite?

    private let api      = AnthropicClient()
    private let executor = FileToolsExecutor()

    private let systemPrompt = """
    You are a helpful AI assistant with full read/write access to this iPhone's filesystem via DarkSword.
    You can read and write any file the user asks about.
    The user is currently debugging a camera issue — the back camera shows a black screen in the Camera \
    app but works in other apps like Roblox.
    Relevant paths to investigate:
    - /var/mobile/Library/Preferences/com.apple.camera.plist
    - /var/mobile/Library/Preferences/com.apple.avfoundation.plist
    - /var/mobile/Library/Logs/CrashReporter/
    - /var/mobile/Library/Caches/com.apple.camera/
    - /tmp/ (FilzaJailedDS logs are here)
    Always back up files before writing. Ask for confirmation before modifying anything.
    For writes, the app will prompt the user for approval automatically — you do not need to ask again.
    """

    // MARK: - Send message

    func send() {
        let text = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !isSending else { return }
        inputText = ""
        isSending = true
        error = nil

        let userMessage = Message(role: .user, content: .text(text))
        messages.append(userMessage)

        Task { await runTurn() }
    }

    // MARK: - Agentic loop

    private func runTurn() async {
        defer { isSending = false }

        // Build conversation for API
        var apiMessages = messages.filter { msg in
            if case .assistantBlocks(let b) = msg.content { return !b.isEmpty }
            return true
        }

        do {
            var response = try await api.send(messages: apiMessages, system: systemPrompt)

            while response.stopReason == "tool_use" {
                // Add assistant turn with the tool-use blocks
                let assistantMsg = Message(role: .assistant, content: .assistantBlocks(response.content))
                messages.append(assistantMsg)
                apiMessages.append(assistantMsg)

                // Execute each tool call
                var toolResults: [Message] = []
                for tu in response.toolUses {
                    let result = await executeToolCall(tu)
                    let resultMsg = Message(
                        role: .user,
                        content: .toolResult(toolUseId: tu.id, result: result)
                    )
                    toolResults.append(resultMsg)
                    apiMessages.append(resultMsg)
                }
                // We don't append the tool-result messages to the visible list —
                // the next assistant text turn gives the user the summary.

                response = try await api.send(messages: apiMessages, system: systemPrompt)
            }

            // Final text response
            let finalText = response.textContent
            if !finalText.isEmpty {
                messages.append(Message(role: .assistant, content: .text(finalText)))
            }

        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: - Tool execution

    private func executeToolCall(_ tu: ToolUseBlock) async -> String {
        // Writes need user approval
        if tu.name == "write_file",
           let path    = tu.input["path"]?.stringValue,
           let content = tu.input["content"]?.stringValue {
            return await requestWriteApproval(path: path, content: content, toolUseId: tu.id)
        }
        return await executor.execute(toolName: tu.name, input: tu.input)
    }

    // MARK: - Write approval

    func requestWriteApproval(path: String, content: String, toolUseId: String) async -> String {
        return await withCheckedContinuation { continuation in
            pendingWrite = PendingWrite(
                path: path,
                preview: String(content.prefix(500)),
                onApprove: {
                    Task {
                        let result = await self.executor.execute(
                            toolName: "write_file",
                            input: ["path": .string(path), "content": .string(content)]
                        )
                        self.pendingWrite = nil
                        continuation.resume(returning: result)
                    }
                },
                onDeny: {
                    self.pendingWrite = nil
                    continuation.resume(returning: "User denied the write to \(path)")
                }
            )
        }
    }

    func clearHistory() {
        messages = []
    }
}

// MARK: - Pending write model

struct PendingWrite {
    let path:      String
    let preview:   String
    let onApprove: () -> Void
    let onDeny:    () -> Void
}
