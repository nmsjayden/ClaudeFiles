import Foundation
import SwiftUI

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var inputText:    String = ""
    @Published var isSending:    Bool   = false
    @Published var error:        String?
    @Published var pendingWrite: PendingWrite?
    @Published var streamingText: String = ""         // current partial assistant text
    @Published var streamingToolCalls: [UUID: ToolCallInfo] = [:]

    private let api      = AnthropicClient()
    private let executor = FileToolsExecutor()
    private let authMgr  = AuthManager.shared

    private var currentTask: Task<Void, Never>?
    unowned let store: ConversationStore

    init(store: ConversationStore) {
        self.store = store
    }

    private let systemPrompt = """
    You are running inside a custom iOS app on a jailbroken device with filesystem access via \
    the DarkSword kernel exploit. You have 5 tools: read_file, write_file, list_directory, \
    search_files, get_file_info.

    FILESYSTEM REALITY on this device:
    - You CAN access the root iOS filesystem: /System, /Applications, /usr, /bin, /sbin, /Library, /tmp
    - /var is a symlink to /private/var, and /tmp is a symlink to /private/tmp — if a /var path \
      fails, ALWAYS try the /private/var equivalent before concluding you lack access
    - /var/mobile/* paths often need to be addressed as /private/var/mobile/* instead
    - User-data directories under /var/mobile/ (Containers, Library/Preferences, Library/Logs) \
      may be gated by Data Protection class keys. If a path returns an error, don't assume it's \
      permanently blocked — try the /private/var/mobile/ form, try a parent directory first to \
      see what's visible, and report what actually happened rather than guessing

    When a tool errors, the exact error message tells you WHY it failed (not found, permission \
    denied, etc.). Use that to decide the next move. Don't give up after one failed path.

    Format responses with markdown: code blocks with language tags, bold for emphasis, lists \
    where helpful. Keep responses focused — don't lecture about what you can't do until you've \
    actually tried. Confirm before writing files.
    """

    var displayMessages: [DisplayMessage] {
        guard let c = store.selected else { return [] }
        var out: [DisplayMessage] = []
        for m in c.messages {
            if m.toolUseId != nil { continue }
            if m.text.isEmpty && (m.apiBlocks?.isEmpty ?? true) { continue }

            // Extract tool calls from stored assistant blocks
            var toolCalls: [ToolCallInfo] = []
            if let blocks = m.apiBlocks {
                for b in blocks where b.type == "tool_use" {
                    if let id = b.id, let name = b.name {
                        toolCalls.append(ToolCallInfo(
                            id: id,
                            name: name,
                            input: b.input ?? [:],
                            result: findResult(for: id, in: c.messages),
                            isComplete: true
                        ))
                    }
                }
            }

            let role: ChatMessage.Role = (m.role == "user") ? .user : .assistant
            out.append(DisplayMessage(role: role, text: m.text, toolCalls: toolCalls))
        }
        return out
    }

    private func findResult(for toolUseId: String, in messages: [StoredMessage]) -> String? {
        messages.first(where: { $0.toolUseId == toolUseId })?.toolResult
    }

    // MARK: - Send

    func send() {
        let text = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !isSending else { return }
        guard var conv = store.selected else { return }
        inputText = ""
        isSending = true
        error = nil
        streamingText = ""
        streamingToolCalls = [:]

        conv.messages.append(StoredMessage(role: "user", text: text,
                                           apiBlocks: nil, toolUseId: nil, toolResult: nil))
        if conv.title == "New chat" {
            conv.title = String(text.prefix(50))
        }
        store.update(conv)

        currentTask = Task { await runTurn() }
    }

    func stopGenerating() {
        currentTask?.cancel()
        currentTask = nil
        // Save partial response if we have any
        if !streamingText.isEmpty, var conv = store.selected {
            conv.messages.append(StoredMessage(
                role: "assistant",
                text: streamingText + "\n\n_[Stopped]_",
                apiBlocks: nil, toolUseId: nil, toolResult: nil
            ))
            store.update(conv)
        }
        streamingText = ""
        streamingToolCalls = [:]
        isSending = false
    }

    // MARK: - Agentic streaming loop

    private func runTurn() async {
        defer { isSending = false; streamingText = ""; streamingToolCalls = [:] }

        guard let token = await authMgr.accessToken() else {
            error = "Not logged in"; return
        }

        do {
            var history = buildAPIHistory()

            while true {
                if Task.isCancelled { return }

                // Track streaming state for this iteration
                var currentText = ""
                var toolBlocks: [Int: StreamingTool] = [:]
                var textBlocks: [Int: String] = [:]
                var finalStopReason: String?

                try await api.sendStreaming(messages: history, system: systemPrompt, accessToken: token) { event in
                    switch event {
                    case .textStart(let idx):
                        textBlocks[idx] = ""
                    case .textDelta(let idx, let delta):
                        textBlocks[idx, default: ""] += delta
                        currentText += delta
                        self.streamingText = currentText
                    case .toolUseStart(let idx, let id, let name):
                        toolBlocks[idx] = StreamingTool(id: id, name: name, partialJSON: "")
                        let info = ToolCallInfo(id: id, name: name, input: [:], result: nil, isComplete: false)
                        self.streamingToolCalls[UUID()] = info
                    case .toolInputDelta(let idx, let partial):
                        toolBlocks[idx]?.partialJSON += partial
                    case .blockStop:
                        break
                    case .messageStop(let reason):
                        finalStopReason = reason
                    }
                }

                // Build the assistant turn to persist and send back
                var apiBlocks: [StoredBlock] = []
                let allIndices = Set(textBlocks.keys).union(toolBlocks.keys).sorted()
                for i in allIndices {
                    if let text = textBlocks[i], !text.isEmpty {
                        apiBlocks.append(StoredBlock(type: "text", text: text, id: nil, name: nil, input: nil))
                    } else if let tool = toolBlocks[i] {
                        let input = parseJSON(tool.partialJSON) ?? [:]
                        apiBlocks.append(StoredBlock(type: "tool_use", text: nil,
                                                     id: tool.id, name: tool.name, input: input))
                    }
                }

                // Combine all text blocks (preserving order)
                let combinedText = allIndices.compactMap { textBlocks[$0] }.joined(separator: "\n")

                DebugLog.log("Turn complete: text=\(combinedText.count) chars, blocks=\(apiBlocks.count), stop=\(finalStopReason ?? "nil")")

                // Append whatever we have (even partial) so user sees the response
                if !apiBlocks.isEmpty || !combinedText.isEmpty {
                    if var conv = store.selected {
                        conv.messages.append(StoredMessage(
                            role: "assistant",
                            text: combinedText,
                            apiBlocks: apiBlocks.isEmpty ? nil : apiBlocks,
                            toolUseId: nil, toolResult: nil
                        ))
                        store.update(conv)
                    }
                }

                streamingText = ""

                // Only continue the loop if the model requested tools
                let hasTools = !toolBlocks.isEmpty
                if !hasTools { return }
                if finalStopReason != nil && finalStopReason != "tool_use" { return }

                // Execute every tool call
                for (_, tool) in toolBlocks.sorted(by: { $0.key < $1.key }) {
                    if Task.isCancelled { return }
                    let input = parseJSON(tool.partialJSON) ?? [:]
                    let toolUseBlock = ToolCallContext(id: tool.id, name: tool.name, input: input)
                    let result = await executeTool(toolUseBlock)
                    if var conv = store.selected {
                        conv.messages.append(StoredMessage(
                            role: "user", text: "",
                            apiBlocks: nil, toolUseId: tool.id, toolResult: result
                        ))
                        store.update(conv)
                    }
                }

                streamingToolCalls = [:]
                history = buildAPIHistory()
            }

        } catch is CancellationError {
            // Already handled by stopGenerating
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func parseJSON(_ s: String) -> [String: AnyJSON]? {
        guard let data = s.data(using: .utf8),
              let obj = try? JSONDecoder().decode([String: AnyJSON].self, from: data) else { return nil }
        return obj
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

    // MARK: - Tool execution

    private struct ToolCallContext {
        let id: String
        let name: String
        let input: [String: AnyJSON]
    }

    private func executeTool(_ tu: ToolCallContext) async -> String {
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
                preview: String(content.prefix(1200)),
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

    // MARK: - User can resend/retry

    func regenerateLast() {
        guard var conv = store.selected else { return }
        // Remove last assistant turn + any trailing tool results
        while let last = conv.messages.last,
              last.role == "assistant" || last.toolUseId != nil {
            conv.messages.removeLast()
        }
        store.update(conv)
        isSending = true
        currentTask = Task { await runTurn() }
    }
}

// MARK: - Models

private struct StreamingTool {
    let id: String
    let name: String
    var partialJSON: String
}

struct ToolCallInfo: Identifiable, Equatable {
    let id: String
    let name: String
    var input: [String: AnyJSON]
    var result: String?
    var isComplete: Bool

    static func == (l: ToolCallInfo, r: ToolCallInfo) -> Bool {
        l.id == r.id && l.isComplete == r.isComplete
    }
}

struct PendingWrite: Identifiable {
    let id       = UUID()
    let path:      String
    let preview:   String
    let onApprove: () -> Void
    let onDeny:    () -> Void
}
