import SwiftUI

struct ChatView: View {
    @StateObject private var vm  = ChatViewModel()
    @EnvironmentObject var auth  : AuthManager

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                messageList
                Divider()
                inputBar
            }
            .navigationTitle("Claude Files")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Clear") { vm.clearHistory() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Logout") { auth.logout() }
                }
            }
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

    // MARK: - Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(vm.displayMessages) { msg in
                        MessageBubble(message: msg).id(msg.id)
                    }
                    if vm.isSending {
                        TypingIndicator().id("typing")
                    }
                }
                .padding()
            }
            .onChange(of: vm.displayMessages.count) { _ in
                if let last = vm.displayMessages.last {
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }

    // MARK: - Input bar

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

// MARK: - Error sheet (copyable)

struct ErrorSheet: View {
    let message: String
    let onDismiss: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Label("Error", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                        .foregroundColor(.red)

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
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.accentColor)
                            .foregroundColor(.white)
                            .cornerRadius(10)
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
