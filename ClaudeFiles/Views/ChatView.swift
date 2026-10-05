import SwiftUI
import UIKit

struct ChatView: View {
    @EnvironmentObject var auth:    AuthManager
    @EnvironmentObject var store:   ConversationStore
    @EnvironmentObject var sandbox: SandboxManager
    @StateObject private var settings = SettingsStore.shared
    @State private var showingSidebar  = false
    @State private var showingSettings = false

    var body: some View {
        ChatContent(store: store, settings: settings, sandbox: sandbox,
                    showingSidebar: $showingSidebar,
                    showingSettings: $showingSettings)
            .environmentObject(auth)
    }
}

// MARK: - Main chat screen

private struct ChatContent: View {
    @ObservedObject var store:    ConversationStore
    @ObservedObject var settings: SettingsStore
    @ObservedObject var sandbox:  SandboxManager
    @Binding var showingSidebar:  Bool
    @Binding var showingSettings: Bool
    @EnvironmentObject var auth: AuthManager
    @StateObject private var vm: ChatViewModel
    @FocusState private var inputFocused: Bool

    init(store: ConversationStore, settings: SettingsStore, sandbox: SandboxManager,
         showingSidebar: Binding<Bool>, showingSettings: Binding<Bool>) {
        self.store    = store
        self.settings = settings
        self.sandbox  = sandbox
        _showingSidebar  = showingSidebar
        _showingSettings = showingSettings
        _vm = StateObject(wrappedValue: ChatViewModel(store: store))
    }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                if vm.displayMessages.isEmpty && vm.streamingText.isEmpty && !vm.isSending {
                    emptyState
                        .contentShape(Rectangle())
                        .onTapGesture { inputFocused = false }
                } else {
                    messageList
                }
                Divider().opacity(0.4)
                inputBar
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { toolbarContent }
        }
        .sheet(isPresented: $showingSidebar)  { ChatListSheet(store: store, isPresented: $showingSidebar) }
        .sheet(isPresented: $showingSettings) { SettingsSheet(settings: settings, sandbox: sandbox) }
        .sheet(item: $vm.pendingWrite)        { WriteApprovalSheet(write: $0) }
        .sheet(isPresented: Binding(get: { vm.error != nil }, set: { if !$0 { vm.error = nil } })) {
            ErrorSheet(message: vm.error ?? "", onDismiss: { vm.error = nil })
        }
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigationBarLeading) {
            Button { haptic(.light); showingSidebar = true } label: {
                Image(systemName: "line.3.horizontal").font(.body.weight(.medium))
            }
        }
        ToolbarItem(placement: .principal) {
            VStack(spacing: 2) {
                Text(store.selected?.title ?? "Chat")
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                HStack(spacing: 4) {
                    // Sandbox status dot
                    Circle()
                        .fill(sandboxDotColor)
                        .frame(width: 5, height: 5)
                    Text(modelShortName)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        ToolbarItem(placement: .navigationBarTrailing) {
            Menu {
                Button { haptic(.light); store.newConversation() } label: {
                    Label("New chat", systemImage: "square.and.pencil")
                }
                if !vm.displayMessages.isEmpty {
                    Button { vm.regenerateLast() } label: {
                        Label("Regenerate", systemImage: "arrow.clockwise")
                    }
                }
                Divider()
                Button { showingSettings = true } label: {
                    Label("Settings", systemImage: "gearshape")
                }
                Divider()
                Button(role: .destructive) { auth.logout() } label: {
                    Label("Logout", systemImage: "rectangle.portrait.and.arrow.right")
                }
            } label: {
                Image(systemName: "ellipsis.circle").font(.body.weight(.medium))
            }
        }
    }

    private var sandboxDotColor: Color {
        switch sandbox.status {
        case .escaped:    return .green
        case .exploiting: return .orange
        case .failed:     return .red
        case .idle:       return .gray
        }
    }

    private var modelShortName: String {
        let full = ModelOption.all.first(where: { $0.id == settings.selectedModel })?.displayName
                   ?? settings.selectedModel
        // Trim "Claude " prefix for brevity
        return full.replacingOccurrences(of: "Claude ", with: "")
    }

    // MARK: - Empty state

    private var emptyState: some View {
        ScrollView {
            VStack(spacing: 0) {
                Spacer().frame(height: 60)

                // App icon silhouette
                ZStack {
                    Circle()
                        .fill(LinearGradient(
                            colors: [Color.accentColor.opacity(0.18), Color.purple.opacity(0.10)],
                            startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 80, height: 80)
                    Image(systemName: "sparkles")
                        .font(.system(size: 34, weight: .semibold))
                        .foregroundStyle(
                            LinearGradient(colors: [.accentColor, .purple],
                                           startPoint: .topLeading, endPoint: .bottomTrailing)
                        )
                }

                Spacer().frame(height: 20)

                Text("What can I help with?")
                    .font(.title2.bold())

                Text("Filesystem access is \(sandboxStatusLabel).")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.top, 6)

                Spacer().frame(height: 36)

                // Suggestion chips
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                    ForEach(suggestions, id: \.0) { suggestion in
                        SuggestionChip(icon: suggestion.0, text: suggestion.1) {
                            vm.inputText = suggestion.2
                            inputFocused = true
                        }
                    }
                }
                .padding(.horizontal, 20)

                Spacer().frame(height: 40)
            }
        }
    }

    private var sandboxStatusLabel: String {
        switch sandbox.status {
        case .escaped:    return "active ✓"
        case .exploiting: return "initialising…"
        case .failed(let m): return "unavailable (\(m))"
        case .idle:       return "pending"
        }
    }

    private var suggestions: [(String, String, String)] {[
        ("folder.badge.questionmark", "List /var/mobile",  "List the contents of /var/mobile"),
        ("doc.text.magnifyingglass",  "Search for .plist", "Search /var/mobile for files matching .plist"),
        ("info.circle",               "System info",       "List /System and tell me about key directories"),
        ("apps.iphone",               "Installed apps",    "List apps installed at /var/containers/Bundle/Application"),
    ]}

    // MARK: - Message list

    @State private var followBottom: Bool = true
    @State private var showJumpButton: Bool = false

    private var messageList: some View {
        ScrollViewReader { proxy in
            GeometryReader { outerGeo in
                ZStack(alignment: .bottom) {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 18) {
                            ForEach(Array(vm.displayMessages.enumerated()), id: \.offset) { idx, msg in
                                MessageBubble(message: msg).id(idx)
                            }

                            // Live streaming bubble
                            if vm.isSending {
                                let liveTools = vm.streamingToolCalls.sorted(by: { $0.key < $1.key })
                                                   .map(\.value)
                                if !vm.streamingText.isEmpty || !liveTools.isEmpty {
                                    StreamingBubble(text: vm.streamingText, toolCalls: liveTools)
                                        .id("streaming")
                                } else {
                                    TypingIndicator().id("typing")
                                }
                            }

                            Color.clear.frame(height: 1).id("bottom")
                                .background(GeometryReader { geo in
                                    Color.clear.preference(
                                        key: BottomDistKey.self,
                                        value: geo.frame(in: .named("scroll")).minY - outerGeo.size.height
                                    )
                                })
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 18)
                    }
                    .coordinateSpace(name: "scroll")
                    .onPreferenceChange(BottomDistKey.self) { dist in
                        let near = dist < 80
                        if followBottom != near { followBottom = near }
                        let show = !near && vm.isSending
                        if show != showJumpButton {
                            withAnimation(.easeOut(duration: 0.2)) { showJumpButton = show }
                        }
                    }
                    .onChange(of: vm.displayMessages.count)    { _ in scrollIfFollowing(proxy) }
                    .onChange(of: vm.streamingText)            { _ in scrollIfFollowing(proxy) }
                    .onChange(of: vm.streamingToolCalls.count) { _ in scrollIfFollowing(proxy) }
                    .onChange(of: vm.isSending) { sending in
                        if sending { followBottom = true; showJumpButton = false; scrollToBottom(proxy) }
                    }
                    .scrollDismissesKeyboard(.interactively)
                    .onTapGesture { inputFocused = false }

                    if showJumpButton {
                        jumpButton(proxy)
                            .padding(.bottom, 10)
                            .transition(.scale.combined(with: .opacity))
                    }
                }
            }
        }
    }

    private func jumpButton(_ proxy: ScrollViewProxy) -> some View {
        Button {
            haptic(.light); followBottom = true; showJumpButton = false
            withAnimation(.easeOut(duration: 0.25)) { proxy.scrollTo("bottom", anchor: .bottom) }
        } label: {
            Image(systemName: "arrow.down")
                .font(.system(size: 14, weight: .bold))
                .foregroundStyle(.primary)
                .frame(width: 36, height: 36)
                .background(Color(.secondarySystemBackground))
                .clipShape(Circle())
                .overlay(Circle().stroke(Color(.separator), lineWidth: 0.5))
                .shadow(color: .black.opacity(0.12), radius: 4, y: 2)
        }
    }

    private func scrollIfFollowing(_ proxy: ScrollViewProxy) {
        guard followBottom else { return }
        scrollToBottom(proxy)
    }
    private func scrollToBottom(_ proxy: ScrollViewProxy) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.03) {
            withAnimation(.easeOut(duration: 0.15)) { proxy.scrollTo("bottom", anchor: .bottom) }
        }
    }

    // MARK: - Input bar

    private var inputBar: some View {
        HStack(alignment: .bottom, spacing: 10) {
            ZStack(alignment: .leading) {
                if vm.inputText.isEmpty {
                    Text("Message Claude…")
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 11)
                        .allowsHitTesting(false)
                }
                TextField("", text: $vm.inputText, axis: .vertical)
                    .lineLimit(1...6)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 11)
                    .focused($inputFocused)
            }
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 22))

            sendOrStopButton
        }
        .padding(.horizontal, 12)
        .padding(.top, 10)
        .padding(.bottom, 12)
        .background(Color(.systemBackground))
    }

    @ViewBuilder
    private var sendOrStopButton: some View {
        if vm.isSending {
            Button { haptic(.medium); vm.stopGenerating() } label: {
                ZStack {
                    Circle().fill(Color.primary).frame(width: 36, height: 36)
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color(.systemBackground))
                        .frame(width: 12, height: 12)
                }
            }
            .transition(.scale.combined(with: .opacity))
        } else {
            Button { haptic(.light); vm.send() } label: {
                ZStack {
                    Circle()
                        .fill(vm.inputText.isEmpty ? Color(.systemGray4) : Color.accentColor)
                        .frame(width: 36, height: 36)
                    Image(systemName: "arrow.up")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(.white)
                }
            }
            .disabled(vm.inputText.isEmpty)
            .transition(.scale.combined(with: .opacity))
        }
    }

    private func haptic(_ style: UIImpactFeedbackGenerator.FeedbackStyle) {
        UIImpactFeedbackGenerator(style: style).impactOccurred()
    }
}

// MARK: - Suggestion chip

private struct SuggestionChip: View {
    let icon:   String
    let text:   String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.accentColor)
                Text(text)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color(.separator), lineWidth: 0.5))
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Message bubble

struct MessageBubble: View {
    let message: DisplayMessage

    var body: some View {
        if message.role == .user {
            HStack {
                Spacer(minLength: 48)
                Text(message.text)
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .background(Color.accentColor)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 20))
                    .textSelection(.enabled)
            }
        } else {
            HStack(alignment: .top, spacing: 10) {
                assistantAvatar
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(message.toolCalls) { ToolCallCard(tool: $0) }
                    if !message.text.isEmpty {
                        MarkdownView(message.text)
                            .textSelection(.enabled)
                    }
                }
                Spacer(minLength: 0)
            }
        }
    }

    private var assistantAvatar: some View {
        Circle()
            .fill(LinearGradient(colors: [.accentColor, .purple],
                                  startPoint: .topLeading, endPoint: .bottomTrailing))
            .frame(width: 28, height: 28)
            .overlay(
                Image(systemName: "sparkles")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(.white)
            )
    }
}

// MARK: - Streaming bubble

struct StreamingBubble: View {
    let text:      String
    let toolCalls: [ToolCallInfo]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(LinearGradient(colors: [.accentColor, .purple],
                                      startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: 28, height: 28)
                .overlay(Image(systemName: "sparkles").font(.system(size: 12, weight: .bold)).foregroundStyle(.white))

            VStack(alignment: .leading, spacing: 8) {
                ForEach(toolCalls) { ToolCallCard(tool: $0) }
                if !text.isEmpty { MarkdownView(text) }
                if text.isEmpty && toolCalls.isEmpty { TypingIndicator() }
            }
            Spacer(minLength: 0)
        }
    }
}

// MARK: - Tool call card

struct ToolCallCard: View {
    let tool: ToolCallInfo
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header row
            Button {
                guard tool.isComplete else { return }
                withAnimation(.easeInOut(duration: 0.18)) { expanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: iconName)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(tool.isComplete ? .accentColor : .orange)
                        .frame(width: 16)

                    Text(humanName)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.primary)

                    if let p = pathArg {
                        Text(p)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer(minLength: 0)

                    if !tool.isComplete {
                        ProgressView().controlSize(.mini).tint(.orange)
                    } else {
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundStyle(.tertiary)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            // Expanded detail
            if expanded, tool.isComplete {
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    if !tool.input.isEmpty {
                        ToolSection(title: "INPUT") {
                            ForEach(tool.input.keys.sorted(), id: \.self) { key in
                                HStack(alignment: .top, spacing: 4) {
                                    Text("\(key):")
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                    Text(valueStr(tool.input[key]))
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.primary)
                                        .textSelection(.enabled)
                                    Spacer(minLength: 0)
                                }
                            }
                        }
                    }
                    ToolSection(title: "RESULT") {
                        if let result = tool.result, !result.isEmpty {
                            ScrollView {
                                Text(result)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .frame(maxHeight: 260)
                        } else {
                            Text("(no output)")
                                .font(.caption).foregroundStyle(.secondary).italic()
                        }
                    }
                }
                .padding(12)
                .background(Color(.tertiarySystemBackground))
            }
        }
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(.separator), lineWidth: 0.5))
    }

    private var iconName: String {
        switch tool.name {
        case "read_file":      return "doc.text"
        case "write_file":     return "pencil.and.outline"
        case "list_directory": return "folder"
        case "search_files":   return "magnifyingglass"
        case "get_file_info":  return "info.circle"
        default:               return "wrench.and.screwdriver"
        }
    }
    private var humanName: String {
        switch tool.name {
        case "read_file":      return "Read"
        case "write_file":     return "Write"
        case "list_directory": return "List"
        case "search_files":   return "Search"
        case "get_file_info":  return "Info"
        default:               return tool.name
        }
    }
    private var pathArg: String? {
        tool.input["path"]?.string ?? tool.input["directory"]?.string
    }
    private func valueStr(_ v: AnyJSON?) -> String {
        guard let v else { return "" }
        switch v {
        case .string(let s): return s
        case .number(let n): return n.truncatingRemainder(dividingBy: 1) == 0 ? "\(Int(n))" : "\(n)"
        case .bool(let b):   return b ? "true" : "false"
        case .null:          return "null"
        default:
            if let d = try? JSONEncoder().encode(v), let s = String(data: d, encoding: .utf8) { return s }
            return "?"
        }
    }
}

private struct ToolSection<Content: View>: View {
    let title:   String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(.tertiary)
                .tracking(1)
            content()
        }
    }
}

// MARK: - Typing indicator

struct TypingIndicator: View {
    @State private var on = false
    var body: some View {
        HStack(spacing: 5) {
            ForEach(0..<3, id: \.self) { i in
                Circle()
                    .fill(Color.secondary.opacity(0.5))
                    .frame(width: 7, height: 7)
                    .scaleEffect(on ? 1 : 0.5)
                    .animation(.easeInOut(duration: 0.55).repeatForever().delay(Double(i) * 0.15), value: on)
            }
        }
        .padding(.vertical, 4)
        .onAppear { on = true }
    }
}

// MARK: - Error sheet

struct ErrorSheet: View {
    let message: String
    let onDismiss: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                        Text("Something went wrong").font(.headline)
                        Spacer()
                    }
                    Text(message)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(Color(.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    Button {
                        UIPasteboard.general.string = message
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: {
                        Label(copied ? "Copied!" : "Copy error",
                              systemImage: copied ? "checkmark" : "doc.on.doc")
                            .frame(maxWidth: .infinity).padding()
                            .background(Color.accentColor)
                            .foregroundStyle(.white)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
                .padding()
            }
            .navigationTitle("Error")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { onDismiss(); dismiss() }
                }
            }
        }
    }
}

// MARK: - Chat list sidebar

struct ChatListSheet: View {
    @ObservedObject var store: ConversationStore
    @Binding var isPresented: Bool
    @State private var renamingId: UUID?
    @State private var renameText  = ""
    @State private var deletingId: UUID?

    var body: some View {
        NavigationView {
            List {
                ForEach(store.conversations) { c in
                    HStack(spacing: 10) {
                        Button {
                            store.selectedId = c.id
                            isPresented = false
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(c.title).foregroundStyle(.primary).lineLimit(1)
                                    Text(c.updatedAt, style: .relative)
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if c.id == store.selectedId {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.accentColor)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)

                        Menu {
                            Button { renamingId = c.id; renameText = c.title } label: {
                                Label("Rename", systemImage: "pencil")
                            }
                            Button(role: .destructive) { deletingId = c.id } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                                .font(.title3).foregroundStyle(.secondary)
                                .frame(width: 32, height: 32).contentShape(Rectangle())
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .listStyle(.plain)
            .navigationTitle("Chats")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { Button("Done") { isPresented = false } }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { store.newConversation(); isPresented = false } label: {
                        Label("New", systemImage: "square.and.pencil").font(.body.weight(.medium))
                    }
                }
            }
            .alert("Rename chat", isPresented: Binding(get: { renamingId != nil }, set: { if !$0 { renamingId = nil } })) {
                TextField("Title", text: $renameText)
                Button("Cancel", role: .cancel) { renamingId = nil }
                Button("Save") {
                    if let id = renamingId { store.rename(id, to: renameText.isEmpty ? "Untitled" : renameText) }
                    renamingId = nil
                }
            }
            .alert("Delete chat?", isPresented: Binding(get: { deletingId != nil }, set: { if !$0 { deletingId = nil } })) {
                Button("Cancel", role: .cancel) { deletingId = nil }
                Button("Delete", role: .destructive) {
                    if let id = deletingId { store.delete(id) }
                    deletingId = nil
                }
            } message: { Text("This cannot be undone.") }
        }
    }
}

// MARK: - Settings sheet

struct SettingsSheet: View {
    @ObservedObject var settings: SettingsStore
    @ObservedObject var sandbox:  SandboxManager
    @Environment(\.dismiss) private var dismiss
    @State private var showDebugLog = false

    var body: some View {
        NavigationView {
            Form {
                // Sandbox status section
                Section("Filesystem") {
                    HStack(spacing: 10) {
                        Image(systemName: sandboxIcon)
                            .foregroundStyle(sandboxColor)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Sandbox escape")
                                .font(.body)
                            Text(sandbox.status.label)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                }

                Section("Debug") {
                    Button { showDebugLog = true } label: {
                        Label("View debug log", systemImage: "doc.text.magnifyingglass")
                    }
                    Button(role: .destructive) { DebugLog.clear() } label: {
                        Label("Clear debug log", systemImage: "trash")
                    }
                }

                ForEach(ModelOption.grouped(), id: \.0) { family, models in
                    Section(family.rawValue) {
                        ForEach(models) { opt in
                            Button { settings.selectedModel = opt.id } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(opt.displayName).foregroundStyle(.primary)
                                        Text(opt.subtitle).font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    if settings.selectedModel == opt.id {
                                        Image(systemName: "checkmark").foregroundStyle(.accentColor)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                        }
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .sheet(isPresented: $showDebugLog) { DebugLogSheet() }
        }
    }

    private var sandboxIcon: String {
        switch sandbox.status {
        case .escaped:    return "checkmark.shield.fill"
        case .exploiting: return "shield.lefthalf.filled"
        case .failed:     return "xmark.shield.fill"
        case .idle:       return "shield"
        }
    }
    private var sandboxColor: Color {
        switch sandbox.status {
        case .escaped:    return .green
        case .exploiting: return .orange
        case .failed:     return .red
        case .idle:       return .gray
        }
    }
}

// MARK: - Debug log viewer

struct DebugLogSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var logText = ""
    @State private var copied  = false

    var body: some View {
        NavigationView {
            ScrollView {
                Text(logText.isEmpty ? "(empty)" : logText)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .navigationTitle("Debug log")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        UIPasteboard.general.string = logText
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    }
                }
            }
            .onAppear { logText = DebugLog.readAll() }
        }
    }
}

// MARK: - Write approval sheet

struct WriteApprovalSheet: View {
    let write: PendingWrite
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 10) {
                        Image(systemName: "pencil.circle.fill")
                            .font(.title3).foregroundStyle(.accentColor)
                        Text("Approve file write?").font(.headline)
                        Spacer()
                    }
                    InfoBlock(label: "PATH", value: write.path, mono: true)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("CONTENT PREVIEW")
                            .font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary).tracking(1)
                        ScrollView {
                            Text(write.preview)
                                .font(.system(.footnote, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                        }
                        .frame(maxHeight: 300)
                        .background(Color(.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                    Label("A `.claudebackup` copy is saved before writing.", systemImage: "checkmark.shield.fill")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding()
            }
            .navigationTitle("Write file")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Deny", role: .destructive) { write.onDeny(); dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Approve") {
                        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                        write.onApprove(); dismiss()
                    }.bold()
                }
            }
        }
    }
}

private struct InfoBlock: View {
    let label: String
    let value: String
    var mono  = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary).tracking(1)
            Text(value)
                .font(mono ? .system(.footnote, design: .monospaced) : .footnote)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }
}

// MARK: - Preference key

private struct BottomDistKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}
