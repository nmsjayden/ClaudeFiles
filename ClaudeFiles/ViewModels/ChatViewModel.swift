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
                var toolBlocks:       [Int: StreamingTool] = [:]
                var textBlocks:       [Int: String]        = [:]
                var compactionBlocks: [Int: String]        = [:]
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
                    case .compactionStart(let idx):
                        compactionBlocks[idx] = ""
                        DebugLog.log("Server-side compaction triggered")
                    case .compactionDelta(let idx, let content):
                        compactionBlocks[idx, default: ""] += content
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
                let allIndices = Set(textBlocks.keys).union(toolBlocks.keys).union(compactionBlocks.keys).sorted()
                for i in allIndices {
                    if let content = compactionBlocks[i], !content.isEmpty {
                        // Compaction block — stored so it's passed back to the API
                        apiBlocks.append(StoredBlock(type: "compaction", text: content,
                                                     id: nil, name: nil, input: nil))
                    } else if let text = textBlocks[i], !text.isEmpty {
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
        // Server-side compaction handles context management automatically.
        // The API compacts older messages when input tokens exceed the threshold
        // set in context_management. Compaction blocks in stored messages are
        // passed back and the API drops everything before them.
        return messagesToAPI(c.messages)
    }

    private func messagesToAPI(_ msgs: [StoredMessage]) -> [ChatMessage] {
        // ── Phase 1: Group stored messages into (assistant, tool_results[]) pairs ──
        // Walk through StoredMessages and collect consecutive tool_result messages
        // that follow each assistant message. This keeps the pairing explicit so
        // Phase 2 can validate each pair independently.

        struct AssistantGroup {
            let blocks: [StoredBlock]   // apiBlocks from the assistant message
            let text: String            // plain text fallback
            var toolResultMsgs: [(toolUseId: String, result: String)]
        }

        var groups: [Any] = []  // Either ChatMessage (user text) or AssistantGroup
        var i = 0

        while i < msgs.count {
            let m = msgs[i]

            if m.toolUseId != nil {
                // Orphaned tool_result not following an assistant group — skip it.
                // (This can happen after a stopped generation or crash.)
                i += 1
                continue
            }

            if m.role == "user" {
                groups.append(ChatMessage(role: .user, content: .text(m.text)))
                i += 1
                continue
            }

            // Assistant message — collect any tool_results that follow it
            var group = AssistantGroup(
                blocks: m.apiBlocks ?? [],
                text: m.text,
                toolResultMsgs: []
            )
            // Gather consecutive tool_result StoredMessages
            while i + 1 < msgs.count,
                  let toolId = msgs[i + 1].toolUseId,
                  let toolResult = msgs[i + 1].toolResult {
                group.toolResultMsgs.append((toolUseId: toolId, result: toolResult))
                i += 1
            }
            groups.append(group)
            i += 1
        }

        // ── Phase 2: Validate each group and build the final ChatMessage array ──
        // For each AssistantGroup:
        //   1. Find the set of tool_use IDs in the assistant blocks
        //   2. Find the set of tool_result IDs collected after it
        //   3. The MATCHED set = intersection of both
        //   4. Only include tool_use blocks whose IDs are in the matched set
        //   5. Only include tool_results whose IDs are in the matched set
        //   6. This guarantees every tool_use has exactly one tool_result and vice versa

        var result: [ChatMessage] = []

        for item in groups {
            if let userMsg = item as? ChatMessage {
                // Avoid consecutive user messages — merge or skip
                if let last = result.last, last.role == .user {
                    // Skip duplicate user messages (shouldn't normally happen)
                }
                result.append(userMsg)
                continue
            }

            guard let group = item as? AssistantGroup else { continue }

            let toolUseIds = Set(group.blocks.compactMap { b -> String? in
                b.type == "tool_use" ? b.id : nil
            })
            let toolResultIds = Set(group.toolResultMsgs.map { $0.toolUseId })

            // Matched = IDs present in BOTH the assistant's tool_use AND the following tool_results
            let matchedIds = toolUseIds.intersection(toolResultIds)

            // Build the assistant message blocks
            var apiBlocks: [APIBlock] = []
            for b in group.blocks {
                if b.type == "tool_use" {
                    // Only include if this tool_use has a matching result
                    guard let id = b.id, matchedIds.contains(id) else { continue }
                }
                apiBlocks.append(APIBlock(type: b.type, text: b.text, id: b.id, name: b.name, input: b.input))
            }

            // Emit the assistant message (only if there's content)
            if !apiBlocks.isEmpty {
                result.append(ChatMessage(role: .assistant, content: .blocks(apiBlocks)))
            } else if !group.text.isEmpty {
                result.append(ChatMessage(role: .assistant, content: .text(group.text)))
            }
            // else: empty assistant message after stripping — drop entirely

            // Build the tool_results user message (only matched IDs)
            let validResults = group.toolResultMsgs.filter { matchedIds.contains($0.toolUseId) }
            if !validResults.isEmpty {
                if validResults.count == 1 {
                    result.append(ChatMessage(role: .user, content: .toolResult(
                        toolUseId: validResults[0].toolUseId, result: validResults[0].result)))
                } else {
                    result.append(ChatMessage(role: .user, content: .toolResults(validResults)))
                }
            }
        }

        // ── Phase 3: Final cleanup ──
        // Remove consecutive same-role messages (can happen after stripping)
        var cleaned: [ChatMessage] = []
        for msg in result {
            if let last = cleaned.last, last.role == msg.role {
                // Skip consecutive same-role (shouldn't happen often after Phase 2)
                // But keep user messages by merging conceptually
                if msg.role == .user {
                    cleaned.append(msg)  // API allows consecutive user only via tool_result
                }
                continue
            }
            cleaned.append(msg)
        }

        // Must start with user message
        while let first = cleaned.first, first.role == .assistant {
            cleaned.removeFirst()
        }

        // Must end with user message
        while let last = cleaned.last, last.role == .assistant {
            cleaned.removeLast()
        }

        return cleaned
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
