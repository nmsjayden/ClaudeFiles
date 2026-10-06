import Foundation
import SwiftUI

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var inputText:    String = ""
    @Published var isSending:    Bool   = false
    @Published var error:        String?
    @Published var pendingWrite: PendingWrite?

    // Live streaming state — keyed by block index so updates apply in-place
    @Published var streamingText:         String = ""
    @Published var streamingToolCalls:    [Int: ToolCallInfo] = [:]
    @Published var activeStreamingConvId: UUID?  // which conv the stream belongs to

    private let api      = AnthropicClient()
    private let executor = FileToolsExecutor()
    private let authMgr  = AuthManager.shared

    private var currentTask: Task<Void, Never>?
    unowned let store: ConversationStore

    init(store: ConversationStore) {
        self.store = store
    }

    // MARK: - System prompt

    private let systemPrompt = """
    You are running inside a custom iOS app on a device with filesystem access via \
    the FilzaJailedDS kernel exploit (opa334). You have 9 tools:
    - read_file, write_file, list_directory, search_files, get_file_info
    - bash_exec: run shell commands (ls, cat, find, ps, uname, etc.)
    - grep_search: search file contents for a pattern
    - head_file, tail_file: read first/last N lines of a file

    FILESYSTEM NOTES:
    - /var is a symlink to /private/var, /tmp → /private/tmp, /etc → /private/etc
    - If a /var path fails, ALWAYS try the /private/var equivalent
    - User-data paths like /var/mobile/* may need /private/var/mobile/*
    - When a tool errors, use the exact error message to decide your next move
    - Use bash_exec for complex operations like piped commands, process listing, etc.

    Always try paths before concluding you lack access. Use markdown in responses: \
    code blocks with language tags, bold for emphasis. Confirm before writing files.
    """

    // MARK: - Display

    var displayMessages: [DisplayMessage] {
        guard let c = store.selected else { return [] }
        var out: [DisplayMessage] = []
        for m in c.messages {
            if m.toolUseId != nil { continue }
            if m.text.isEmpty && (m.apiBlocks?.isEmpty ?? true) { continue }

            var toolCalls: [ToolCallInfo] = []
            if let blocks = m.apiBlocks {
                for b in blocks where b.type == "tool_use" {
                    if let id = b.id, let name = b.name {
                        toolCalls.append(ToolCallInfo(
                            id: id, name: name,
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

    /// Only show the streaming bubble if the active stream belongs to the currently selected conv.
    var streamingBelongsToCurrentChat: Bool {
        guard let active = activeStreamingConvId, let selected = store.selectedId
        else { return false }
        return active == selected
    }

    private func findResult(for toolUseId: String, in messages: [StoredMessage]) -> String? {
        messages.first(where: { $0.toolUseId == toolUseId })?.toolResult
    }

    // MARK: - Send

    func send() {
        let text = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, !isSending else { return }
        guard let convId = store.selectedId else { return }

        inputText = ""
        isSending = true
        error = nil
        streamingText = ""
        streamingToolCalls = [:]
        activeStreamingConvId = convId

        // Append user message + maybe set title
        store.mutateById(convId) { conv in
            conv.messages.append(StoredMessage(role: "user", text: text,
                                               apiBlocks: nil, toolUseId: nil, toolResult: nil))
            if conv.title == "New chat" { conv.title = String(text.prefix(50)) }
        }

        currentTask = Task { await runTurn(convId: convId) }
    }

    func stopGenerating() {
        currentTask?.cancel()
        currentTask = nil
        if !streamingText.isEmpty, let convId = activeStreamingConvId {
            store.appendMessage(to: convId, StoredMessage(
                role: "assistant",
                text: streamingText + "\n\n_[Stopped]_",
                apiBlocks: nil, toolUseId: nil, toolResult: nil
            ))
        }
        resetStreaming()
    }

    private func resetStreaming() {
        streamingText = ""
        streamingToolCalls = [:]
        activeStreamingConvId = nil
        isSending = false
    }

    // MARK: - Streaming loop

    private func runTurn(convId: UUID) async {
        defer { resetStreaming() }

        do {
            var history = buildAPIHistory(convId: convId)

            while true {
                if Task.isCancelled { return }

                // Re-fetch token each iteration so refreshed tokens are picked up
                guard let token = await authMgr.accessToken() else { error = "Not logged in"; return }

                var currentText = ""
                var toolBlocks:  [Int: StreamingTool] = [:]
                var textBlocks:  [Int: String]        = [:]
                var finalStopReason: String?

                try await api.sendStreaming(messages: history, system: systemPrompt,
                                            accessToken: token) { [weak self] event in
                    guard let self else { return }
                    switch event {
                    case .textStart(let idx):
                        textBlocks[idx] = ""
                    case .textDelta(let idx, let delta):
                        textBlocks[idx, default: ""] += delta
                        currentText += delta
                        self.streamingText = currentText
                    case .toolUseStart(let idx, let id, let name):
                        toolBlocks[idx] = StreamingTool(id: id, name: name, partialJSON: "")
                        self.streamingToolCalls[idx] = ToolCallInfo(
                            id: id, name: name, input: [:], result: nil, isComplete: false)
                    case .toolInputDelta(let idx, let partial):
                        toolBlocks[idx]?.partialJSON += partial
                        if let raw = toolBlocks[idx]?.partialJSON,
                           let parsed = self.parseJSON(raw) {
                            self.streamingToolCalls[idx]?.input = parsed
                        }
                    case .blockStop(let idx):
                        if toolBlocks[idx] != nil {
                            self.streamingToolCalls[idx]?.isComplete = true
                        }
                    case .messageStop(let reason):
                        finalStopReason = reason
                    case .statusMessage(let msg):
                        self.streamingText = "⏳ \(msg)"
                    }
                }

                // Build persistent blocks
                var apiBlocks: [StoredBlock] = []
                let allIndices = Set(textBlocks.keys).union(toolBlocks.keys).sorted()
                for i in allIndices {
                    if let text = textBlocks[i], !text.isEmpty {
                        apiBlocks.append(StoredBlock(type: "text", text: text,
                                                     id: nil, name: nil, input: nil))
                    } else if let tool = toolBlocks[i] {
                        let input = parseJSON(tool.partialJSON) ?? [:]
                        apiBlocks.append(StoredBlock(type: "tool_use", text: nil,
                                                     id: tool.id, name: tool.name, input: input))
                    }
                }
                let combinedText = allIndices.compactMap { textBlocks[$0] }.joined(separator: "\n")

                DebugLog.log("Turn: text=\(combinedText.count)c blocks=\(apiBlocks.count) stop=\(finalStopReason ?? "nil")")

                if !apiBlocks.isEmpty || !combinedText.isEmpty {
                    store.appendMessage(to: convId, StoredMessage(
                        role: "assistant", text: combinedText,
                        apiBlocks: apiBlocks.isEmpty ? nil : apiBlocks,
                        toolUseId: nil, toolResult: nil
                    ))
                }
                streamingText = ""

                // Handle refusal
                if finalStopReason == "refusal" {
                    if combinedText.isEmpty {
                        store.appendMessage(to: convId, StoredMessage(
                            role: "assistant",
                            text: "_Claude declined this request._",
                            apiBlocks: nil, toolUseId: nil, toolResult: nil
                        ))
                    }
                    return
                }

                let hasTools = !toolBlocks.isEmpty
                if !hasTools { return }
                if let reason = finalStopReason, reason != "tool_use" { return }

                // Execute tools sequentially
                for (_, tool) in toolBlocks.sorted(by: { $0.key < $1.key }) {
                    if Task.isCancelled { return }
                    let input  = parseJSON(tool.partialJSON) ?? [:]
                    let result = await executeTool(id: tool.id, name: tool.name, input: input)
                    store.appendMessage(to: convId, StoredMessage(
                        role: "user", text: "",
                        apiBlocks: nil, toolUseId: tool.id, toolResult: result
                    ))
                }

                streamingToolCalls = [:]
                history = buildAPIHistory(convId: convId)
            }
        } catch is CancellationError {
            // handled by stopGenerating
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func parseJSON(_ s: String) -> [String: AnyJSON]? {
        guard let data = s.data(using: .utf8),
              let obj = try? JSONDecoder().decode([String: AnyJSON].self, from: data) else { return nil }
        return obj
    }

    private func buildAPIHistory(convId: UUID) -> [ChatMessage] {
        guard let c = store.conversations.first(where: { $0.id == convId }) else { return [] }
        let all = c.messages

        // Estimate tokens (~4 chars/token). If over threshold, compact older messages.
        let maxEstimatedTokens = 24_000   // keep ~24k tokens, leaves room for response
        let keepRecentTurns    = 6        // always keep last N messages verbatim

        let totalChars = all.reduce(0) { $0 + estimateChars($1) }
        let estimatedTokens = totalChars / 4

        if estimatedTokens > maxEstimatedTokens && all.count > keepRecentTurns + 2 {
            return compactedHistory(messages: all, keepRecent: keepRecentTurns)
        }

        return messagesToAPI(all)
    }

    /// Rough character count for a stored message
    private func estimateChars(_ m: StoredMessage) -> Int {
        var count = m.text.count
        if let blocks = m.apiBlocks {
            for b in blocks {
                count += (b.text?.count ?? 0) + 80 // tool calls add overhead
                if let input = b.input {
                    for (_, v) in input {
                        if case .string(let s) = v { count += s.count }
                    }
                }
            }
        }
        count += m.toolResult?.count ?? 0
        return count
    }

    /// Build compacted history: summarize older turns, keep recent ones verbatim
    private func compactedHistory(messages: [StoredMessage], keepRecent: Int) -> [ChatMessage] {
        let splitAt = max(0, messages.count - keepRecent)
        let older  = Array(messages[..<splitAt])
        var recent = Array(messages[splitAt...])

        // Collect tool_use IDs that exist in the recent slice (from assistant blocks)
        var recentToolUseIds = Set<String>()
        for m in recent {
            if let blocks = m.apiBlocks {
                for b in blocks where b.type == "tool_use" {
                    if let id = b.id { recentToolUseIds.insert(id) }
                }
            }
        }

        // Strip orphaned tool_result messages at the start of recent slice —
        // these reference tool_use IDs that were in the compacted (dropped) portion.
        // The API requires every tool_result to have a matching tool_use in the
        // previous assistant message, so orphans cause HTTP 400.
        while let first = recent.first,
              let toolId = first.toolUseId,
              !recentToolUseIds.contains(toolId) {
            recent.removeFirst()
        }

        // Build a text summary of older messages
        var summaryParts: [String] = []
        for m in older {
            if m.toolUseId != nil { continue } // skip raw tool results
            let role = m.role == "user" ? "User" : "Assistant"
            if !m.text.isEmpty {
                let truncated = m.text.count > 200 ? String(m.text.prefix(200)) + "…" : m.text
                summaryParts.append("\(role): \(truncated)")
            }
            if let blocks = m.apiBlocks {
                for b in blocks where b.type == "tool_use" {
                    if let name = b.name, let path = b.input?["path"]?.string {
                        summaryParts.append("  [Tool: \(name) → \(path)]")
                    } else if let name = b.name {
                        summaryParts.append("  [Tool: \(name)]")
                    }
                }
            }
        }

        let summary = "[Context compacted — earlier conversation summary]\n" +
            summaryParts.joined(separator: "\n")

        DebugLog.log("Compacted: \(older.count) older messages → summary (\(summary.count)c), keeping \(recent.count) recent")

        var result: [ChatMessage] = []
        result.append(ChatMessage(role: .user, content: .text(summary)))
        result.append(ChatMessage(role: .assistant, content: .text("Understood, I have the context from our earlier conversation.")))

        let recentAPI = messagesToAPI(Array(recent))

        // If recentAPI starts with an assistant message, we'd have consecutive
        // assistant messages (the summary ack + the first recent). Skip leading
        // assistant messages from the recent slice to keep alternation valid.
        var startIdx = 0
        for msg in recentAPI {
            if msg.role == .assistant { startIdx += 1 } else { break }
        }
        result += Array(recentAPI[startIdx...])
        return result
    }

    private func messagesToAPI(_ msgs: [StoredMessage]) -> [ChatMessage] {
        var result: [ChatMessage] = []
        var i = 0
        while i < msgs.count {
            let m = msgs[i]

            if let toolId = m.toolUseId, let toolResult = m.toolResult {
                // Collect ALL consecutive tool_result messages into one user message.
                // The API requires all tool_results for a given assistant turn to be
                // in a single user message, not separate ones.
                var toolResults: [(toolUseId: String, result: String)] = [
                    (toolUseId: toolId, result: toolResult)
                ]
                while i + 1 < msgs.count,
                      let nextToolId = msgs[i + 1].toolUseId,
                      let nextResult = msgs[i + 1].toolResult {
                    toolResults.append((toolUseId: nextToolId, result: nextResult))
                    i += 1
                }
                if toolResults.count == 1 {
                    result.append(ChatMessage(role: .user, content: .toolResult(
                        toolUseId: toolResults[0].toolUseId, result: toolResults[0].result)))
                } else {
                    result.append(ChatMessage(role: .user, content: .toolResults(toolResults)))
                }
            } else if m.role == "user" {
                result.append(ChatMessage(role: .user, content: .text(m.text)))
            } else if let blocks = m.apiBlocks, !blocks.isEmpty {
                let apiBlocks = blocks.map {
                    APIBlock(type: $0.type, text: $0.text, id: $0.id, name: $0.name, input: $0.input)
                }
                result.append(ChatMessage(role: .assistant, content: .blocks(apiBlocks)))
            } else {
                result.append(ChatMessage(role: .assistant, content: .text(m.text)))
            }
            i += 1
        }

        // Ensure conversation ends with a user message (API requirement).
        while let last = result.last, last.role == .assistant {
            result.removeLast()
        }

        return result
    }

    // MARK: - Tool execution

    private func executeTool(id: String, name: String, input: [String: AnyJSON]) async -> String {
        if name == "write_file",
           let path    = input["path"]?.string,
           let content = input["content"]?.string {
            if SettingsStore.shared.autoApproveWrites {
                return await executor.execute(name: name, input: input)
            }
            return await requestWriteApproval(path: path, content: content)
        }
        return await executor.execute(name: name, input: input)
    }

    private func requestWriteApproval(path: String, content: String) async -> String {
        await withCheckedContinuation { cont in
            pendingWrite = PendingWrite(
                path: path, preview: String(content.prefix(1200)),
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

    func regenerateLast() {
        guard let convId = store.selectedId else { return }
        store.mutateById(convId) { conv in
            while let last = conv.messages.last,
                  last.role == "assistant" || last.toolUseId != nil {
                conv.messages.removeLast()
            }
        }
        isSending = true
        activeStreamingConvId = convId
        currentTask = Task { await runTurn(convId: convId) }
    }
}

// MARK: - Support types

private struct StreamingTool {
    let id: String
    let name: String
    var partialJSON: String
}

struct ToolCallInfo: Identifiable, Equatable {
    let id:    String
    let name:  String
    var input: [String: AnyJSON]
    var result: String?
    var isComplete: Bool

    static func == (l: ToolCallInfo, r: ToolCallInfo) -> Bool {
        l.id == r.id && l.isComplete == r.isComplete && l.result == r.result
    }
}

struct PendingWrite: Identifiable {
    let id       = UUID()
    let path:      String
    let preview:   String
    let onApprove: () -> Void
    let onDeny:    () -> Void
}
