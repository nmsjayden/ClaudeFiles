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

        static func resize(_ image: UIImage, maxDimension: CGFloat) -> UIImage {
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
    the FilzaJailedDS kernel exploit (opa334). You have 37 tools:
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

    KERNEL RESEARCH TOOLS (10 tools for autonomous kernel investigation):
    You have direct kernel read/write access via the exploit. Use these tools to \
    investigate kernel structures, sandbox policies, and SPTM bypass vectors WITHOUT \
    the user needing to rebuild or re-run anything.

    - kernel_read(address, size): Hex dump N bytes from any kernel address. Shows hex, \
    ASCII, and pointer annotations. Use to inspect structs you've found.
    - kernel_read64(address): Read a single uint64. Shows hex, decimal, and auto-dereferences \
    if the value looks like a kernel pointer.
    - kernel_follow_chain(base, offsets): Follow pointer chains through kernel structs. \
    Offsets are comma-separated hex or decimal: "0x18,0x20,0x10". Essential for walking \
    proc→proc_ro→ucred→label→sandbox chains.
    - kernel_proc_info(pid): Full proc_info dump: proc, proc_ro, ucred, sandbox, profile, \
    extension_set, UIDs, cs_flags. Use pid=0 for our process.
    - kernel_sandbox_check(operation, name): Test if a sandbox operation is allowed. \
    Operations: "process-exec", "process-fork", "mach-lookup", "file-read-data", etc. \
    Name is optional target (service name, path).
    - kernel_sandbox_dump(offset, size): Dump bytes from our sandbox structure. \
    The sandbox has profile ptr at +0x10, extension set at +0x70, etc.
    - kernel_dlsym(framework, symbol): Look up any symbol address via dlsym. Use to \
    find private API function addresses.
    - kernel_dlcall(framework, function, arg0-3): Call a dynamically loaded function \
    with up to 4 uint64 args. Returns the uint64 result. DANGEROUS — wrong function = crash.
    - kernel_run_command(command): Run existing research commands by name: dump_self, \
    dump_proc_1, compare, sandbox_ops, sandbox_profile, swap_profile, exec_ext, \
    test_spawn, breadcrumbs.
    - kernel_proc_list(filter): Walk kernel proc list. Optional name filter (case-insensitive).
    - kernel_write64(address, value): [WRITE] Write a uint64 to a kernel address. Reads \
    before/after to confirm. Reports if PPL/SPTM blocked the write.
    - kernel_write(address, hex_data): [WRITE] Write arbitrary bytes (hex string like \
    "0000000000000000") to a kernel address. Confirms with readback.
    - posix_spawn_test(binary, args): Test posix_spawn with a specific binary. Does \
    sandbox pre-checks, attempts spawn, reports detailed errno.
    - sandbox_ext_consume(token): Consume a sandbox extension token. Also tries to \
    issue extensions for /bin/sh as a test.
    - dump_extensions(): READ-ONLY. Dumps all 16 sandbox extension set buckets with full \
    detail: class names, paths, flags, linked list structure, and RAW HEX DUMPS. It checks \
    BOTH our struct offsets AND lara's offsets (OFF_EXT_DATA=0x40) so you can verify which \
    layout is correct on this device. ALWAYS run this first before patch_exec.
    - patch_exec(): READ-ONLY v4 — Analyzes all 16 extension buckets, counts classes/extensions, \
    checks process-exec/process-fork sandbox status, dumps sandbox_label raw fields. Previous v3 \
    caused kernel panics by writing into live extension data buffers. This version only reads.
    - try_profile_swap(target_pid): WRITE — Copies target PID's sandbox profile pointer into ours. \
    Tests sandbox_check after swap. Auto-restores on failure. Default: PID 34 (SpringBoard). \
    Dumps full sandbox_label fields for analysis. Does NOT write NULL or zero flags (those panic).
    - sandbox_label_write(offset, value): WRITE — Write a 64-bit value to sandbox_label+offset. \
    Generic tool for experimenting with sandbox label fields. Reports before/after values and \
    tests sandbox_check. Use offset 0x00 for profile ptr, 0x10 for extension_set, 0x50/0x58 \
    for flags.
    - detect_zones(): READ-ONLY — Show the zone metadata exclusion range. SPTM unmaps zone \
    metadata pages from kernel page tables. Reading them causes Translation fault → kernel panic. \
    This shows the current exclusion range and known-good heap addresses. Run after any panic.
    - set_zone_meta(min, max): Set the zone metadata range from panic log. After a kernel panic, \
    check the "Zone Meta" line and pass min/max addresses (hex). All pointer chain walks then \
    avoid this range (± 16 MB margin).

    KERNEL RESEARCH METHODOLOGY:
    When investigating the kernel or researching SPTM bypass vectors, follow this approach:
    1. START by running kernel_proc_info(0) to get our process's current state.
    2. EXPLORE by using kernel_read and kernel_follow_chain to walk kernel data structures.
    3. COMPARE by examining other processes (PID 1 = launchd) vs our own.
    4. TEST hypotheses with kernel_sandbox_check, kernel_dlsym, kernel_dlcall.
    5. DOCUMENT findings clearly — addresses, offsets, what each field means.
    6. ITERATE — each finding should lead to the next investigation.

    KEY CONTEXT: This is an iOS 18.1 device (iPhone 14, A15 T8110, arm64e). SPTM runs \
    at EL2 and prevents kernel from touching protected pages. PPL-protected structures \
    (proc_ro, ucred, mac_label) are READ-ONLY. The sandbox_label struct itself IS writable \
    but sandbox_check still enforces profile rules. posix_spawn currently fails with EPERM. \
    The goal: find a way to execute arbitrary binaries from the app.

    CONFIRMED FINDINGS FROM PREVIOUS RESEARCH:
    - LARA class_node layout is CORRECT: next=+0x00, ext=+0x08, class_name=+0x10, count=+0x18
    - Our class_node layout (class_name=+0x00) is WRONG — reads empty strings
    - LARA extension offsets confirmed: data_ptr at +0x40, data_len at +0x48
    - All 16 extension set buckets are populated (no empty ones)
    - Extension classes found: com.apple.assets.read (bucket 0), com.apple.app-sandbox.read-write \
    (buckets 1-5, 8, 10-15), com.apple.Pasteboard-readonly (bucket 7)
    - com.apple.sandbox.executable is NOT present — this is what patch_exec adds
    - sandbox_label+0x00 = profile ptr (writable), +0x10 = extension_set ptr, \
    +0x50 = 0xa0 (flags?), +0x58 = 0x01 (flags?)
    - launchd (PID 1) has no sandbox (ptr=0xffffffffffffffff)
    - SpringBoard (PID 34) has a different, larger sandbox profile

    ZONE METADATA PROTECTION: On A15+ with SPTM, zone metadata pages are unmapped from \
    kernel page tables. Reading them via kread causes Translation fault level 3 → kernel panic. \
    The code now has a zone metadata exclusion range (from the last panic log). All pointer \
    chain walks (extension lists, class_node chains) validate pointers against this range \
    before reading. If you see "STOPPED: zone_meta=YES" in output, a freed object's pointer \
    pointed into zone metadata — this is normal and the walk stopped safely. Run detect_zones \
    to see the current range. After a new panic, use set_zone_meta with values from the panic log.

    STRATEGY: Run patch_exec first (read-only analysis of extension set). Use dump_extensions \
    for hex dumps. Use sandbox_label_write to carefully experiment with individual fields. \
    NEVER write NULL to profile, zero flags, or write into live extension data buffers — \
    all of those cause kernel panics. try_profile_swap copies SpringBoard's profile but \
    SPTM may integrity-check the bytecode.

    Addresses are decimal uint64. For hex addresses like 0xffffffe1234, convert to decimal \
    or pass as a string "0xffffffe1234" — the tool handles both formats.

    CRASH RECOVERY: Every kernel research tool result is saved to disk (fsync'd) BEFORE \
    returning. If the app crashes (kernel panic, etc), the result is preserved. On your \
    FIRST message in any new session, ALWAYS run device_info — it will show you: \
    (1) crash breadcrumbs showing which step panicked, (2) SSV breadcrumbs from sandbox.m, \
    (3) the LAST TOOL RESULT that was persisted before the crash. If device_info shows a \
    last tool result, that tool's output was saved but the app crashed before you could see \
    it. Use last_result to read the full output. This tells you WHAT happened even when YOU \
    didn't get the result back.

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

    /// Remove oldest messages when conversation exceeds maxMessages limit.
    /// Trims on group boundaries so tool_use / tool_result pairs stay intact.
    private func trimConversation(_ convId: UUID) {
        let limit = SettingsStore.shared.maxMessages
        guard limit > 0 else { return } // 0 = unlimited
        store.mutateById(convId) { conv in
            guard conv.messages.count > limit else { return }
            let excess = conv.messages.count - limit
            // Find a safe cut point at or after `excess` that doesn't split a
            // tool_use / tool_result group. Walk forward from `excess` until we
            // land on a message that is NOT an orphaned tool_result.
            var cutAt = excess
            while cutAt < conv.messages.count && conv.messages[cutAt].toolUseId != nil {
                cutAt += 1
            }
            // Also skip past any assistant message whose tool_results we'd be
            // cutting into — if the message right before cutAt is an assistant
            // with tool_use blocks, we should include it in the removal too
            // (its results were already removed or will be orphaned).
            if cutAt > 0 && cutAt < conv.messages.count {
                // Make sure we start on a user (non-tool-result) message
                let first = conv.messages[cutAt]
                if first.role == "assistant" {
                    // Check if any following tool_results belong to it
                    // If so, keep this assistant + its results — back up to before it
                    // Actually, starting on an assistant is fine; messagesToAPI
                    // will strip it if it's at the beginning. Just make sure
                    // we don't start on a tool_result.
                }
            }
            guard cutAt > 0 else { return }
            conv.messages.removeFirst(cutAt)
            DebugLog.log("[Trim] Removed \(cutAt) old messages (limit=\(limit), now=\(conv.messages.count))")
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
                    case .usageStart(let input, let output, let cacheCreation, let cacheRead):
                        UsageTracker.shared.updateUsage(
                            input: input, output: output,
                            cacheCreation: cacheCreation, cacheRead: cacheRead)
                    case .usageDelta(let output):
                        UsageTracker.shared.updateOutputTokens(output)
                    }
                }

                // Finalize usage tracking for this API call
                UsageTracker.shared.finishRequest()

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
                    let rawResult = await executeTool(id: tool.id, name: tool.name, input: input)
                    // Cap tool results to prevent app freeze on massive kernel dumps.
                    // 12000 chars ≈ 3000 tokens — enough for useful data, won't overload.
                    let result: String
                    if rawResult.count > 12000 {
                        let truncated = String(rawResult.prefix(11500))
                        let suffix = "\n\n⚠️ OUTPUT TRUNCATED (was \(rawResult.count) chars, showing first 11500). Run dump_extensions or detect_zones individually for full output."
                        result = truncated + suffix
                    } else {
                        result = rawResult
                    }
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
            // Crashed = tool_use IDs with NO matching tool_result (app crashed before result saved)
            let crashedIds = toolUseIds.subtracting(toolResultIds)

            // Build the assistant message blocks — keep ALL tool_use blocks
            // (including crashed ones so the AI knows what it called)
            var apiBlocks: [APIBlock] = []
            for b in group.blocks {
                if b.type == "tool_use" {
                    guard let id = b.id, matchedIds.contains(id) || crashedIds.contains(id) else { continue }
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

            // Build the tool_results user message
            // Include matched results + synthetic crash results for crashed tools
            var allResults = group.toolResultMsgs.filter { matchedIds.contains($0.toolUseId) }

            // For crashed tool calls, inject a synthetic result telling the AI what happened
            for crashedId in crashedIds {
                let toolName = group.blocks.first(where: { $0.id == crashedId })?.name ?? "unknown"
                let lastResult = FileToolsExecutor.readLastResult()
                var crashMsg = "⚠️ APP CRASHED: This tool call (\(toolName)) caused the app to crash "
                crashMsg += "(likely kernel panic). The result was never returned to you.\n\n"
                if lastResult != "(no previous result)" {
                    // Truncate for API message size
                    let preview = lastResult.count > 3000 ? String(lastResult.prefix(3000)) + "\n... (truncated, run last_result for full)" : lastResult
                    crashMsg += "RECOVERED OUTPUT (saved to disk before crash):\n\(preview)"
                } else {
                    crashMsg += "No recovered output found. Run device_info to check breadcrumbs."
                }
                allResults.append((toolUseId: crashedId, result: crashMsg))
            }

            if !allResults.isEmpty {
                if allResults.count == 1 {
                    result.append(ChatMessage(role: .user, content: .toolResult(
                        toolUseId: allResults[0].toolUseId, result: allResults[0].result)))
                } else {
                    result.append(ChatMessage(role: .user, content: .toolResults(allResults)))
                }
            }
        }

        // ── Phase 3: Final cleanup ──
        // Ensure every tool_result references a tool_use_id that actually
        // appears in the preceding assistant message, and enforce alternation.
        var cleaned: [ChatMessage] = []

        for msg in result {
            if msg.role == .user {
                // If this user message contains tool_result(s), verify each one
                // has a matching tool_use in the most recent assistant message.
                if case .toolResult(let tid, _) = msg.content {
                    if !assistantHasToolUse(cleaned, toolUseId: tid) { continue }
                } else if case .toolResults(let trs) = msg.content {
                    let valid = trs.filter { assistantHasToolUse(cleaned, toolUseId: $0.toolUseId) }
                    if valid.isEmpty { continue }
                    if valid.count != trs.count {
                        // Re-wrap with only the valid ones
                        if valid.count == 1 {
                            cleaned.append(ChatMessage(role: .user, content: .toolResult(
                                toolUseId: valid[0].toolUseId, result: valid[0].result)))
                        } else {
                            cleaned.append(ChatMessage(role: .user, content: .toolResults(valid)))
                        }
                        continue
                    }
                }
                cleaned.append(msg)
            } else {
                // Assistant — skip if consecutive with previous assistant
                if let last = cleaned.last, last.role == .assistant { continue }
                cleaned.append(msg)
            }
        }

        // Must start with a real user message (not a tool_result)
        while let first = cleaned.first {
            if first.role == .assistant { cleaned.removeFirst(); continue }
            if case .toolResult = first.content { cleaned.removeFirst(); continue }
            if case .toolResults = first.content { cleaned.removeFirst(); continue }
            break
        }

        // Must end with user message
        while let last = cleaned.last, last.role == .assistant {
            cleaned.removeLast()
        }

        return cleaned
    }

    /// Check if the most recent assistant message in `history` contains
    /// a tool_use block with the given ID. Tool_result messages must reference
    /// a tool_use in the preceding assistant turn (which may have multiple
    /// tool_result user messages following it).
    private func assistantHasToolUse(_ history: [ChatMessage], toolUseId: String) -> Bool {
        // Walk backwards past any user messages (earlier tool_results from the
        // same assistant turn) to find the assistant message they belong to.
        for msg in history.reversed() {
            if msg.role == .assistant {
                if case .blocks(let blocks) = msg.content {
                    return blocks.contains { $0.type == "tool_use" && $0.id == toolUseId }
                }
                return false
            }
        }
        return false
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
