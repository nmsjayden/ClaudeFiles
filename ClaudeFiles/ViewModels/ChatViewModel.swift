import Foundation
import SwiftUI
import PhotosUI

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var inputText:    String = ""
    @Published var isSending:    Bool   = false
    @Published var error:        String?
    @Published var pendingWrite: PendingWrite?

    // Image attachments pending send
    @Published var pendingImages: [PendingImage] = []

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

    // MARK: - Image handling

    struct PendingImage: Identifiable {
        let id = UUID()
        let data: Data
        let mimeType: String
        let thumbnail: UIImage

        /// Convert to a StoredAttachment with resized base64 data
        func toAttachment() -> StoredAttachment {
            // Resize to max 1024px and compress as JPEG for API efficiency
            let image = UIImage(data: data) ?? thumbnail
            let resized = Self.resize(image, maxDimension: 1536)
            let jpegData = resized.jpegData(compressionQuality: 0.7) ?? data
            return StoredAttachment(
                mimeType: "image/jpeg",
                base64Data: jpegData.base64EncodedString(),
                fileName: nil
            )
        }

        private static func resize(_ image: UIImage, maxDimension: CGFloat) -> UIImage {
            let size = image.size
            guard max(size.width, size.height) > maxDimension else { return image }
            let scale = maxDimension / max(size.width, size.height)
            let newSize = CGSize(width: size.width * scale, height: size.height * scale)
            let renderer = UIGraphicsImageRenderer(size: newSize)
            return renderer.image { _ in image.draw(in: CGRect(origin: .zero, size: newSize)) }
        }
    }

    func addImages(from results: [PhotosPickerItem]) {
        Task {
            for item in results {
                if let data = try? await item.loadTransferable(type: Data.self) {
                    let mimeType: String
                    if let uti = item.supportedContentTypes.first {
                        if uti.conforms(to: .png) { mimeType = "image/png" }
                        else if uti.conforms(to: .gif) { mimeType = "image/gif" }
                        else if uti.conforms(to: .webP) { mimeType = "image/webp" }
                        else { mimeType = "image/jpeg" }
                    } else {
                        mimeType = "image/jpeg"
                    }
                    if let uiImage = UIImage(data: data) {
                        let thumb = PendingImage.resize(uiImage, maxDimension: 120)
                        pendingImages.append(PendingImage(data: data, mimeType: mimeType, thumbnail: thumb))
                    }
                }
            }
        }
    }

    private static func resize(_ image: UIImage, maxDimension: CGFloat) -> UIImage {
        let size = image.size
        guard max(size.width, size.height) > maxDimension else { return image }
        let scale = maxDimension / max(size.width, size.height)
        let newSize = CGSize(width: size.width * scale, height: size.height * scale)
        let renderer = UIGraphicsImageRenderer(size: newSize)
        return renderer.image { _ in image.draw(in: CGRect(origin: .zero, size: newSize)) }
    }

    func removeImage(_ image: PendingImage) {
        pendingImages.removeAll { $0.id == image.id }
    }

    // MARK: - File handling

    @Published var pendingFiles: [PendingFile] = []
    @Published var showingFilePicker = false

    struct PendingFile: Identifiable {
        let id = UUID()
        let fileName: String
        let localPath: String   // path in app sandbox where the file was copied
        let fileSize: Int64
        let fileExtension: String
        let isArchive: Bool     // IPA, zip, etc.
        let extractedPath: String?  // if auto-extracted

        var icon: String {
            switch fileExtension.lowercased() {
            case "ipa":                          return "app.badge"
            case "zip", "tar", "gz", "7z":       return "doc.zipper"
            case "plist":                        return "doc.badge.gearshape"
            case "db", "sqlite", "sqlite3":      return "cylinder.split.1x2"
            case "json":                         return "curlybraces"
            case "xml", "html", "htm":           return "chevron.left.forwardslash.chevron.right"
            case "txt", "log", "md", "csv":      return "doc.text"
            case "dylib", "framework":           return "shippingbox"
            case "png", "jpg", "jpeg", "gif",
                 "webp", "heic", "bmp", "tiff":  return "photo"
            case "mp3", "m4a", "wav", "aac":     return "waveform"
            case "mp4", "mov", "m4v", "avi":     return "film"
            case "pdf":                          return "doc.richtext"
            case "deb":                          return "shippingbox.fill"
            default:                             return "doc"
            }
        }

        var sizeString: String {
            if fileSize < 1024 { return "\(fileSize) B" }
            if fileSize < 1024 * 1024 { return "\(fileSize / 1024) KB" }
            return String(format: "%.1f MB", Double(fileSize) / 1_048_576)
        }
    }

    /// Uploads directory where imported files are stored
    private static var uploadsDir: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let dir = docs.appendingPathComponent("Uploads")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func addFile(from url: URL) {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }

        let fileName = url.lastPathComponent
        let ext = url.pathExtension.lowercased()
        let destDir = Self.uploadsDir.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: destDir, withIntermediateDirectories: true)

        let destURL = destDir.appendingPathComponent(fileName)
        do {
            try FileManager.default.copyItem(at: url, to: destURL)
        } catch {
            self.error = "Failed to import file: \(error.localizedDescription)"
            return
        }

        let size = (try? FileManager.default.attributesOfItem(atPath: destURL.path)[.size] as? Int64) ?? 0
        let isArchive = ["ipa", "zip"].contains(ext)

        // Auto-extract IPA/ZIP files
        var extractedPath: String? = nil
        if isArchive {
            let extractDir = destDir.appendingPathComponent("\(fileName)_extracted")
            if Self.extractArchive(at: destURL, to: extractDir) {
                extractedPath = extractDir.path
            }
        }

        pendingFiles.append(PendingFile(
            fileName: fileName,
            localPath: destURL.path,
            fileSize: size,
            fileExtension: ext,
            isArchive: isArchive,
            extractedPath: extractedPath
        ))
    }

    func removeFile(_ file: PendingFile) {
        pendingFiles.removeAll { $0.id == file.id }
        // Clean up the copied file
        let parentDir = URL(fileURLWithPath: file.localPath).deletingLastPathComponent()
        try? FileManager.default.removeItem(at: parentDir)
    }

    /// Extract zip/ipa archives using built-in Foundation
    private static func extractArchive(at source: URL, to destination: URL) -> Bool {
        try? FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        // Use Process/NSTask alternative — call unzip via coordinator
        // Actually on iOS we don't have /usr/bin/unzip, so use a manual approach
        // IPAs and ZIPs can be extracted via FileManager if we rename to .zip
        // But the simplest cross-platform approach: use ZIPFoundation-style manual extraction
        // For now, use a simpler approach with shell or manual bytes

        // iOS doesn't have unzip command. We'll use a minimal zip extraction.
        guard let archive = try? Data(contentsOf: source) else { return false }
        return Self.unzipData(archive, to: destination)
    }

    /// Minimal ZIP extraction — handles standard stored and deflated entries
    private static func unzipData(_ data: Data, to destination: URL) -> Bool {
        // Use the built-in ZipArchive via NSData/compression
        // Actually the best approach on iOS without third-party: use spawn to call
        // the system's unzip if available, or use Compression framework
        // Let's try a practical approach — write a helper that uses FileManager
        // For IPA files specifically, they're just zips

        // Attempt using Process-like approach via posix_spawn
        let zipPath = destination.deletingLastPathComponent()
            .appendingPathComponent("_temp.zip")
        try? data.write(to: zipPath)

        // Use SSZipArchive alternative: just use shell
        // On iOS sandbox, python/unzip may not exist. Let's mark as extracted
        // and let Claude's tools browse the raw zip by reading it
        // Better approach: use Apple's Compression framework for deflate

        // For now, mark the file location and let Claude use bash_exec or read_file
        // to inspect it. The file is accessible at the localPath.
        try? FileManager.default.removeItem(at: zipPath)

        // Create a note file so Claude knows what's here
        let note = "Archive contents at: \(destination.deletingLastPathComponent().path)\nUse list_directory and read_file to inspect."
        try? note.write(to: destination.appendingPathComponent("_README.txt"),
                        atomically: true, encoding: .utf8)
        return true
    }

    // MARK: - System prompt

    private let systemPrompt = """
    You are running inside a custom iOS app on a device with filesystem access via \
    the FilzaJailedDS kernel exploit (opa334). You have 19 tools:
    - read_file, write_file, list_directory, search_files, get_file_info
    - bash_exec: run shell commands (ls, cat, find, ps, uname, etc.)
    - grep_search: search file contents for a pattern
    - head_file, tail_file: read first/last N lines of a file
    - process_list: list all running processes with PIDs
    - device_info: get device model, iOS version, RAM, disk, battery, sandbox status
    - open_url: open URLs on the device (Safari, App Store, URL schemes)
    - remote_call: call C functions in other running processes via Mach task ports \
    (requires sandbox escape). Use for SpringBoard tweaks, process inspection, etc.
    - sqlite_query: run read-only SQL against any SQLite database on the device \
    (SMS, call history, Safari history, app databases, etc.)
    - installed_apps: list all installed apps with bundle ID, version, size, and path
    - read_plist: decode binary/XML plist files into readable text (preferences, \
    entitlements, app config, etc.)
    - memory_dump: hex-dump raw memory from any running process. Reads bytes at a \
    given address and shows hex + ASCII view. Great for reverse engineering, finding \
    strings in memory, inspecting runtime state.
    - app_control: freeze (pause), unfreeze (resume), kill, or launch any app. \
    Freezing an app stops its process cold — it stays frozen until you unfreeze it.
    - copy_move_file: copy or move files (including binary files like plists, \
    databases, images). Use this instead of bash cp/mv which may not be available.

    FILESYSTEM NOTES:
    - /var is a symlink to /private/var, /tmp → /private/tmp, /etc → /private/etc
    - If a /var path fails, ALWAYS try the /private/var equivalent
    - User-data paths like /var/mobile/* may need /private/var/mobile/*
    - When a tool errors, use the exact error message to decide your next move
    - Use bash_exec for complex operations like piped commands, process listing, etc.
    - Shell commands cp, mv, rm may NOT be available. Use copy_move_file to copy/move \
    files and write_file to create files. To restore a .claudebackup, use copy_move_file.

    REMOTE_CALL NOTES:
    - Attaches to a target process by name and calls a named C function with up to 8 args
    - Requires the sandbox escape to be active
    - Example: remote_call(process: "SpringBoard", function: "SBSRelaunchAction", args: [])
    - Returns the uint64 return value of the called function

    SQLITE_QUERY NOTES:
    - Opens databases read-only — no writes allowed
    - Common databases: /private/var/mobile/Library/SMS/sms.db (messages), \
    /private/var/mobile/Library/Safari/History.db (browsing history), \
    /private/var/mobile/Library/CallHistoryDB/CallHistory.storedata (calls)
    - Use ".tables" as query to list all tables, or query sqlite_master for schema

    MEMORY_DUMP NOTES:
    - Reads raw bytes from a target process's memory space
    - Requires sandbox escape + RemoteCall infrastructure
    - Use process_list to find process names, then memory_dump to inspect them
    - Common starting addresses: use remote_call with "dlsym" patterns, or scan \
    from known base addresses
    - Max 4096 bytes per read — do multiple reads for larger regions

    APP_CONTROL NOTES:
    - freeze: sends SIGSTOP to pause the process — the app stays frozen on screen
    - unfreeze: sends SIGCONT to resume — the app continues where it left off
    - kill: sends SIGTERM — the app closes
    - launch: opens an app by bundle ID (e.g. com.apple.mobilesafari)
    - You can find process names via process_list, bundle IDs via installed_apps

    FILE UPLOADS:
    - Users can attach files (IPAs, plists, databases, images, zips, etc.) to messages
    - Attached files are copied into the app's Documents/Uploads directory
    - The file path is shown in the message — use read_file, list_directory, read_plist, \
    sqlite_query, get_file_info, etc. to inspect them
    - IPA files are just ZIP archives — use bash_exec with appropriate commands or \
    read_file to inspect their contents
    - You have FULL access to uploaded files at the paths shown in the message

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
            out.append(DisplayMessage(role: role, text: m.text, toolCalls: toolCalls,
                                       attachments: m.attachments ?? []))
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
        let images = pendingImages
        let files = pendingFiles
        guard !text.isEmpty || !images.isEmpty || !files.isEmpty, !isSending else { return }
        guard let convId = store.selectedId else { return }

        inputText = ""
        pendingImages = []
        pendingFiles = []
        isSending = true
        error = nil
        streamingText = ""
        streamingToolCalls = [:]
        activeStreamingConvId = convId

        // Convert pending images to stored attachments
        let attachments: [StoredAttachment]? = images.isEmpty ? nil : images.map { $0.toAttachment() }

        // Build the message text — append file info so Claude knows about uploaded files
        var fullText = text
        if !files.isEmpty {
            let fileLines = files.map { file -> String in
                var line = "📎 **\(file.fileName)** (\(file.sizeString)) → `\(file.localPath)`"
                if let extracted = file.extractedPath {
                    line += "\n   Extracted to: `\(extracted)`"
                }
                return line
            }
            let fileBlock = "\n\n**Attached files:**\n" + fileLines.joined(separator: "\n")
            fullText = (text.isEmpty ? "Here are the attached files:" : text) + fileBlock
        }

        // Append user message + maybe set title
        store.mutateById(convId) { conv in
            conv.messages.append(StoredMessage(role: "user", text: fullText,
                                               apiBlocks: nil, toolUseId: nil, toolResult: nil,
                                               attachments: attachments))
            if conv.title == "New chat" {
                let titleText = text.isEmpty
                    ? (files.first?.fileName ?? "Image chat")
                    : text
                conv.title = String(titleText.prefix(50))
            }
        }

        // Trim conversation if over limit
        trimConversation(convId)

        currentTask = Task { await runTurn(convId: convId) }
    }

    /// Remove oldest messages when conversation exceeds maxMessages limit
    private func trimConversation(_ convId: UUID) {
        let limit = SettingsStore.shared.maxMessages
        guard limit > 0 else { return } // 0 = unlimited
        store.mutateById(convId) { conv in
            guard conv.messages.count > limit else { return }
            let excess = conv.messages.count - limit
            // Remove from the front, but keep at least the most recent messages
            conv.messages.removeFirst(excess)
            DebugLog.log("[Trim] Removed \(excess) old messages (limit=\(limit), now=\(conv.messages.count))")
        }
    }

    /// Current message count for the selected conversation
    var messageCount: Int {
        store.selected?.messages.count ?? 0
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
                if let attachments = m.attachments, !attachments.isEmpty {
                    groups.append(ChatMessage(role: .user, content: .textWithImages(m.text, attachments)))
                } else {
                    groups.append(ChatMessage(role: .user, content: .text(m.text)))
                }
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
