import SwiftUI
import UIKit

struct ChatView: View {
    @EnvironmentObject var auth:  AuthManager
    @EnvironmentObject var store: ConversationStore
    @StateObject private var settings = SettingsStore.shared
    @State private var showingSidebar  = false
    @State private var showingSettings = false

    var body: some View {
        ChatViewContent(store: store, settings: settings,
                        showingSidebar: $showingSidebar,
                        showingSettings: $showingSettings)
            .environmentObject(auth)
    }
}

private struct ChatViewContent: View {
    @ObservedObject var store: ConversationStore
    @ObservedObject var settings: SettingsStore
    @Binding var showingSidebar: Bool
    @Binding var showingSettings: Bool
    @EnvironmentObject var auth: AuthManager
    @StateObject private var vm: ChatViewModel

    init(store: ConversationStore, settings: SettingsStore,
         showingSidebar: Binding<Bool>, showingSettings: Binding<Bool>) {
        self.store = store
        self.settings = settings
        self._showingSidebar  = showingSidebar
        self._showingSettings = showingSettings
        self._vm = StateObject(wrappedValue: ChatViewModel(store: store))
    }

    @FocusState private var inputFocused: Bool

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                if vm.displayMessages.isEmpty && vm.streamingText.isEmpty {
                    emptyState
                        .contentShape(Rectangle())
                        .onTapGesture { inputFocused = false }
                } else {
                    messageList
                }
                Divider()
                inputBar
            }
            .animation(.easeInOut(duration: 0.2), value: vm.isSending)
            .navigationTitle(store.selected?.title ?? "Chat")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { 
                        haptic(.light)
                        showingSidebar = true
                    } label: {
                        Image(systemName: "line.3.horizontal")
                            .font(.body.weight(.medium))
                    }
                }
                ToolbarItem(placement: .principal) {
                    VStack(spacing: 1) {
                        Text(store.selected?.title ?? "Chat")
                            .font(.subheadline.weight(.semibold))
                            .lineLimit(1)
                        Text(modelDisplayName)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button {
                            haptic(.light)
                            store.newConversation()
                        } label: {
                            Label("New chat", systemImage: "square.and.pencil")
                        }
                        Button { showingSettings = true } label: {
                            Label("Settings", systemImage: "gearshape")
                        }
                        if !vm.displayMessages.isEmpty {
                            Button {
                                vm.regenerateLast()
                            } label: {
                                Label("Regenerate response", systemImage: "arrow.clockwise")
                            }
                        }
                        Divider()
                        Button(role: .destructive) { auth.logout() } label: {
                            Label("Logout", systemImage: "rectangle.portrait.and.arrow.right")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .font(.body.weight(.medium))
                    }
                }
            }
        }
        .sheet(isPresented: $showingSidebar) {
            ChatListSheet(store: store, isPresented: $showingSidebar)
        }
        .sheet(isPresented: $showingSettings) {
            SettingsSheet(settings: settings)
        }
        .sheet(item: $vm.pendingWrite) { write in
            WriteApprovalSheet(write: write)
        }
        .sheet(isPresented: Binding(
            get: { vm.error != nil },
            set: { if !$0 { vm.error = nil } }
        )) {
            ErrorSheet(message: vm.error ?? "", onDismiss: { vm.error = nil })
        }
    }

    private var modelDisplayName: String {
        ModelOption.all.first(where: { $0.id == settings.selectedModel })?.displayName ?? settings.selectedModel
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "sparkles")
                .font(.system(size: 44))
                .foregroundStyle(.linearGradient(colors: [.accentColor, .purple], startPoint: .top, endPoint: .bottom))
            Text("What can I help with?")
                .font(.title3.bold())
            Text("I have access to your filesystem via DarkSword.\nAsk me anything.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Spacer()
        }
        .padding(.horizontal, 32)
        .frame(maxWidth: .infinity)
    }

    // MARK: - Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    ForEach(Array(vm.displayMessages.enumerated()), id: \.offset) { idx, msg in
                        MessageBubble(message: msg).id(idx)
                    }

                    // Streaming assistant bubble
                    if vm.isSending && (!vm.streamingText.isEmpty || !vm.streamingToolCalls.isEmpty) {
                        StreamingBubble(text: vm.streamingText, toolCalls: Array(vm.streamingToolCalls.values))
                            .id("streaming")
                    } else if vm.isSending {
                        TypingIndicator().id("typing")
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 16)
            }
            .onChange(of: vm.displayMessages.count) { _ in scrollToBottom(proxy) }
            .onChange(of: vm.streamingText) { _ in scrollToBottom(proxy) }
            .onChange(of: vm.streamingToolCalls.count) { _ in scrollToBottom(proxy) }
            .onChange(of: vm.isSending) { newValue in
                if newValue { scrollToBottom(proxy) }
            }
            .scrollDismissesKeyboard(.interactively)
            .onTapGesture { inputFocused = false }
        }
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
            withAnimation(.easeOut(duration: 0.15)) {
                if vm.isSending {
                    proxy.scrollTo("streaming", anchor: .bottom)
                    proxy.scrollTo("typing", anchor: .bottom)
                } else if !vm.displayMessages.isEmpty {
                    proxy.scrollTo(vm.displayMessages.count - 1, anchor: .bottom)
                }
            }
        }
    }

    // MARK: - Input bar

    private var inputBar: some View {
        HStack(alignment: .bottom, spacing: 8) {
            ZStack(alignment: .leading) {
                if vm.inputText.isEmpty {
                    Text("Message Claude…")
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .allowsHitTesting(false)
                }
                TextField("", text: $vm.inputText, axis: .vertical)
                    .lineLimit(1...6)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .focused($inputFocused)
                    .submitLabel(.send)
            }
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 22))

            sendOrStopButton
        }
        .padding(.horizontal, 10)
        .padding(.top, 8)
        .padding(.bottom, 10)
        .background(Color(.systemBackground))
    }

    @ViewBuilder
    private var sendOrStopButton: some View {
        if vm.isSending {
            Button {
                haptic(.medium)
                vm.stopGenerating()
            } label: {
                ZStack {
                    Circle().fill(Color.primary).frame(width: 36, height: 36)
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color(.systemBackground))
                        .frame(width: 12, height: 12)
                }
            }
            .transition(.scale.combined(with: .opacity))
        } else {
            Button {
                haptic(.light)
                vm.send()
            } label: {
                ZStack {
                    Circle()
                        .fill(vm.inputText.isEmpty ? Color(.systemGray4) : Color.accentColor)
                        .frame(width: 36, height: 36)
                    Image(systemName: "arrow.up")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.white)
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

// MARK: - Bubble

struct MessageBubble: View {
    let message: DisplayMessage

    var body: some View {
        if message.role == .user {
            HStack {
                Spacer(minLength: 40)
                Text(message.text)
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .background(Color.accentColor)
                    .foregroundColor(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 20))
                    .textSelection(.enabled)
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top, spacing: 10) {
                    assistantAvatar
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(message.toolCalls) { tool in
                            ToolCallCard(tool: tool)
                        }
                        if !message.text.isEmpty {
                            MarkdownView(message.text)
                                .textSelection(.enabled)
                        }
                    }
                    Spacer(minLength: 0)
                }
            }
        }
    }

    private var assistantAvatar: some View {
        Circle()
            .fill(.linearGradient(colors: [.accentColor, .purple],
                                   startPoint: .topLeading, endPoint: .bottomTrailing))
            .frame(width: 28, height: 28)
            .overlay(Image(systemName: "sparkles").font(.system(size: 12, weight: .bold)).foregroundColor(.white))
    }
}

// MARK: - Streaming bubble (live during generation)

struct StreamingBubble: View {
    let text:      String
    let toolCalls: [ToolCallInfo]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Circle()
                .fill(.linearGradient(colors: [.accentColor, .purple],
                                       startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: 28, height: 28)
                .overlay(Image(systemName: "sparkles").font(.system(size: 12, weight: .bold)).foregroundColor(.white))

            VStack(alignment: .leading, spacing: 8) {
                ForEach(toolCalls) { tool in
                    ToolCallCard(tool: tool)
                }
                if !text.isEmpty {
                    MarkdownView(text)
                }
                if text.isEmpty && toolCalls.isEmpty {
                    TypingIndicator()
                }
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
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: iconName)
                        .font(.caption)
                        .foregroundColor(tool.isComplete ? .accentColor : .orange)
                    Text(humanName)
                        .font(.caption.weight(.semibold))
                        .foregroundColor(.primary)
                    if let p = pathArg {
                        Text(p)
                            .font(.caption.monospaced())
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    if !tool.isComplete {
                        ProgressView().controlSize(.mini)
                    } else {
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded, let result = tool.result {
                Divider()
                ScrollView {
                    Text(result)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                }
                .frame(maxHeight: 250)
                .background(Color(.tertiarySystemBackground))
            }
        }
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(.separator), lineWidth: 0.5))
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
        case "read_file":      return "Read file"
        case "write_file":     return "Write file"
        case "list_directory": return "List directory"
        case "search_files":   return "Search files"
        case "get_file_info":  return "File info"
        default:               return tool.name
        }
    }
    private var pathArg: String? {
        tool.input["path"]?.string ?? tool.input["directory"]?.string
    }
}

// MARK: - Typing indicator

struct TypingIndicator: View {
    @State private var on = false
    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<3, id: \.self) { i in
                Circle().fill(Color.secondary.opacity(0.5))
                    .frame(width: 7, height: 7)
                    .scaleEffect(on ? 1 : 0.5)
                    .animation(.easeInOut(duration: 0.6).repeatForever().delay(Double(i) * 0.15), value: on)
            }
        }
        .padding(.vertical, 4)
        .onAppear { on = true }
    }
}

// MARK: - Error sheet

struct ErrorSheet: View {
    let message:   String
    let onDismiss: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text("Something went wrong").font(.headline)
                        Spacer()
                    }

                    Text(message)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(10)

                    Button {
                        UIPasteboard.general.string = message
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: {
                        Label(copied ? "Copied!" : "Copy error",
                              systemImage: copied ? "checkmark" : "doc.on.doc")
                            .frame(maxWidth: .infinity).padding()
                            .background(Color.accentColor)
                            .foregroundColor(.white).cornerRadius(12)
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
    @State private var renameText: String = ""
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
                                    Text(c.title)
                                        .foregroundColor(.primary)
                                        .lineLimit(1)
                                    Text(c.updatedAt, style: .relative)
                                        .font(.caption).foregroundColor(.secondary)
                                }
                                Spacer()
                                if c.id == store.selectedId {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(.accentColor)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)

                        Menu {
                            Button {
                                renamingId = c.id
                                renameText = c.title
                            } label: {
                                Label("Rename", systemImage: "pencil")
                            }
                            Button(role: .destructive) {
                                deletingId = c.id
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                                .font(.title3)
                                .foregroundColor(.secondary)
                                .frame(width: 32, height: 32)
                                .contentShape(Rectangle())
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .listStyle(.plain)
            .navigationTitle("Chats")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Done") { isPresented = false }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        store.newConversation()
                        isPresented = false
                    } label: {
                        Label("New", systemImage: "square.and.pencil").font(.body.weight(.medium))
                    }
                }
            }
            .alert("Rename chat", isPresented: Binding(
                get: { renamingId != nil },
                set: { if !$0 { renamingId = nil } }
            )) {
                TextField("Title", text: $renameText)
                Button("Cancel", role: .cancel) { renamingId = nil }
                Button("Save") {
                    if let id = renamingId {
                        store.rename(id, to: renameText.isEmpty ? "Untitled" : renameText)
                    }
                    renamingId = nil
                }
            }
            .alert("Delete chat?", isPresented: Binding(
                get: { deletingId != nil },
                set: { if !$0 { deletingId = nil } }
            )) {
                Button("Cancel", role: .cancel) { deletingId = nil }
                Button("Delete", role: .destructive) {
                    if let id = deletingId { store.delete(id) }
                    deletingId = nil
                }
            } message: {
                Text("This cannot be undone.")
            }
        }
    }
}

// MARK: - Settings

struct SettingsSheet: View {
    @ObservedObject var settings: SettingsStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            Form {
                ForEach(ModelOption.grouped(), id: \.0) { family, models in
                    Section(family.rawValue) {
                        ForEach(models) { opt in
                            Button {
                                settings.selectedModel = opt.id
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(opt.displayName).foregroundColor(.primary)
                                        Text(opt.subtitle)
                                            .font(.caption).foregroundColor(.secondary)
                                    }
                                    Spacer()
                                    if settings.selectedModel == opt.id {
                                        Image(systemName: "checkmark").foregroundColor(.accentColor)
                                    }
                                }
                                .contentShape(Rectangle())
                            }
                        }
                    }
                }

                Section {
                    EmptyView()
                } footer: {
                    Text("Model is used for new messages. Existing chats continue with the model that generated them.")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

// MARK: - Write approval

struct WriteApprovalSheet: View {
    let write: PendingWrite
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 10) {
                        Image(systemName: "pencil.circle.fill")
                            .font(.title3)
                            .foregroundColor(.accentColor)
                        Text("Approve file write?")
                            .font(.headline)
                        Spacer()
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("PATH").font(.caption2.bold()).foregroundColor(.secondary)
                        Text(write.path).font(.system(.footnote, design: .monospaced))
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(.secondarySystemBackground)).cornerRadius(8)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("CONTENT PREVIEW").font(.caption2.bold()).foregroundColor(.secondary)
                        ScrollView {
                            Text(write.preview).font(.system(.footnote, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(10)
                        }
                        .frame(maxHeight: 300)
                        .background(Color(.secondarySystemBackground)).cornerRadius(8)
                    }

                    Label("A `.claudebackup` copy is saved before writing.",
                          systemImage: "checkmark.shield.fill")
                        .font(.caption).foregroundColor(.secondary)
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
