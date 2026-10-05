import SwiftUI

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

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                messageList
                Divider()
                inputBar
            }
            .navigationTitle(store.selected?.title ?? "Chat")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { showingSidebar = true } label: {
                        Image(systemName: "line.3.horizontal")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button { store.newConversation() } label: {
                            Label("New chat", systemImage: "square.and.pencil")
                        }
                        Button { showingSettings = true } label: {
                            Label("Settings", systemImage: "gearshape")
                        }
                        Divider()
                        Button(role: .destructive) { auth.logout() } label: {
                            Label("Logout", systemImage: "rectangle.portrait.and.arrow.right")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
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

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(Array(vm.displayMessages.enumerated()), id: \.offset) { idx, msg in
                        MessageBubble(message: msg).id(idx)
                    }
                    if vm.isSending {
                        TypingIndicator().id("typing")
                    }
                }
                .padding()
            }
            .onChange(of: vm.displayMessages.count) { _ in
                let count = vm.displayMessages.count
                if count > 0 {
                    withAnimation { proxy.scrollTo(count - 1, anchor: .bottom) }
                }
            }
        }
    }

    private var inputBar: some View {
        HStack(spacing: 8) {
            TextField("Message…", text: $vm.inputText, axis: .vertical)
                .lineLimit(1...5)
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(20)
                .onSubmit { vm.send() }

            Button(action: vm.send) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.system(size: 32))
                    .foregroundColor(vm.inputText.isEmpty || vm.isSending ? .secondary : .accentColor)
            }
            .disabled(vm.inputText.isEmpty || vm.isSending)
        }
        .padding(.horizontal).padding(.vertical, 8)
        .background(Color(.systemBackground))
    }
}

// MARK: - Bubble

struct MessageBubble: View {
    let message: DisplayMessage
    private var isUser: Bool { message.role == .user }

    var body: some View {
        HStack(alignment: .bottom, spacing: 6) {
            if !isUser {
                Circle().fill(Color.accentColor).frame(width: 26, height: 26)
                    .overlay(Text("C").font(.caption.bold()).foregroundColor(.white))
            } else {
                Spacer(minLength: 40)
            }

            Text(message.text.isEmpty ? " " : message.text)
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(isUser ? Color.accentColor : Color(.secondarySystemBackground))
                .foregroundColor(isUser ? .white : .primary)
                .cornerRadius(18)
                .textSelection(.enabled)
                .frame(maxWidth: UIScreen.main.bounds.width * 0.75,
                       alignment: isUser ? .trailing : .leading)

            if isUser {
                Circle().fill(Color(.systemGray4)).frame(width: 26, height: 26)
                    .overlay(Image(systemName: "person.fill").font(.caption).foregroundColor(.secondary))
            } else {
                Spacer(minLength: 40)
            }
        }
    }
}

// MARK: - Typing

struct TypingIndicator: View {
    @State private var on = false
    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<3, id: \.self) { i in
                Circle().fill(Color.secondary).frame(width: 8, height: 8)
                    .scaleEffect(on ? 1 : 0.5)
                    .animation(.easeInOut(duration: 0.5).repeatForever().delay(Double(i) * 0.15), value: on)
            }
        }
        .padding(12)
        .background(Color(.secondarySystemBackground)).cornerRadius(18)
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
                    Label("Error", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline).foregroundColor(.red)

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
                            .foregroundColor(.white).cornerRadius(10)
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

    var body: some View {
        NavigationView {
            List {
                ForEach(store.conversations) { c in
                    Button {
                        store.selectedId = c.id
                        isPresented = false
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.title).foregroundColor(.primary).lineLimit(1)
                                Text(c.updatedAt, style: .relative)
                                    .font(.caption).foregroundColor(.secondary)
                            }
                            Spacer()
                            if c.id == store.selectedId {
                                Image(systemName: "checkmark").foregroundColor(.accentColor)
                            }
                        }
                    }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) { store.delete(c.id) } label: {
                            Label("Delete", systemImage: "trash")
                        }
                        Button {
                            renamingId = c.id
                            renameText = c.title
                        } label: {
                            Label("Rename", systemImage: "pencil")
                        }.tint(.blue)
                    }
                }
            }
            .navigationTitle("Chats")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        store.newConversation()
                        isPresented = false
                    } label: {
                        Image(systemName: "square.and.pencil")
                    }
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Done") { isPresented = false }
                }
            }
            .alert("Rename chat", isPresented: Binding(
                get: { renamingId != nil },
                set: { if !$0 { renamingId = nil } }
            )) {
                TextField("Title", text: $renameText)
                Button("Cancel", role: .cancel) { renamingId = nil }
                Button("Save") {
                    if let id = renamingId { store.rename(id, to: renameText) }
                    renamingId = nil
                }
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
                Section {
                    ForEach(ModelOption.all) { opt in
                        Button {
                            settings.selectedModel = opt.id
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(opt.displayName).foregroundColor(.primary)
                                    Text(opt.subtitle).font(.caption).foregroundColor(.secondary)
                                }
                                Spacer()
                                if settings.selectedModel == opt.id {
                                    Image(systemName: "checkmark").foregroundColor(.accentColor)
                                }
                            }
                        }
                    }
                } header: {
                    Text("Model")
                } footer: {
                    Text("Model used for new messages. Existing chats continue with the model that generated them.")
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
                    Label("Claude wants to write a file", systemImage: "pencil.circle.fill")
                        .font(.headline)

                    Group {
                        label("Path")
                        mono(write.path)
                        label("Content preview")
                        mono(write.preview)
                    }

                    Text("A .claudebackup copy is saved automatically before writing.")
                        .font(.caption).foregroundColor(.secondary)
                }
                .padding()
            }
            .navigationTitle("Approve Write?")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Deny", role: .destructive) { write.onDeny(); dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Approve") { write.onApprove(); dismiss() }.bold()
                }
            }
        }
    }

    private func label(_ t: String) -> some View {
        Text(t).font(.caption.bold()).foregroundColor(.secondary)
    }
    private func mono(_ t: String) -> some View {
        Text(t).font(.system(.footnote, design: .monospaced))
            .padding(8).background(Color(.secondarySystemBackground)).cornerRadius(8)
    }
}
