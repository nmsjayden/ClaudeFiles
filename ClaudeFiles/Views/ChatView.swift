import SwiftUI

struct ChatView: View {
    @StateObject private var vm = ChatViewModel()
    @EnvironmentObject var authManager: AuthManager

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Message list
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            ForEach(vm.messages) { msg in
                                MessageBubble(message: msg)
                                    .id(msg.id)
                            }
                            if vm.isSending {
                                TypingIndicator()
                                    .id("typing")
                            }
                        }
                        .padding()
                    }
                    .onChange(of: vm.messages.count) { _ in
                        if let last = vm.messages.last {
                            withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                        }
                    }
                    .onChange(of: vm.isSending) { _ in
                        if vm.isSending {
                            withAnimation { proxy.scrollTo("typing", anchor: .bottom) }
                        }
                    }
                }

                Divider()

                // Input bar
                HStack(spacing: 8) {
                    TextField("Message Claude…", text: $vm.inputText, axis: .vertical)
                        .lineLimit(1...5)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(20)
                        .onSubmit { if !vm.isSending { vm.send() } }

                    Button(action: vm.send) {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 32))
                            .foregroundColor(vm.inputText.isEmpty || vm.isSending ? .secondary : .accentColor)
                    }
                    .disabled(vm.inputText.isEmpty || vm.isSending)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color(.systemBackground))
            }
            .navigationTitle("Claude Files")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Clear") { vm.clearHistory() }
                        .font(.subheadline)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Logout") { authManager.logout() }
                        .font(.subheadline)
                }
            }
        }
        // Write approval sheet
        .sheet(item: Binding(
            get: { vm.pendingWrite.map { WriteWrapper($0) } },
            set: { _ in }
        )) { wrapper in
            WriteApprovalSheet(write: wrapper.write)
        }
        // Error toast
        .overlay(alignment: .top) {
            if let err = vm.error {
                Text(err)
                    .font(.caption)
                    .padding(10)
                    .background(Color.red.opacity(0.9))
                    .foregroundColor(.white)
                    .cornerRadius(8)
                    .padding(.top, 8)
                    .transition(.move(edge: .top))
            }
        }
        .animation(.easeInOut, value: vm.error)
    }
}

// MARK: - Message bubble

struct MessageBubble: View {
    let message: Message

    var body: some View {
        HStack(alignment: .bottom, spacing: 8) {
            if message.role == .assistant {
                Circle()
                    .fill(Color.accentColor)
                    .frame(width: 28, height: 28)
                    .overlay(Text("C").font(.caption.bold()).foregroundColor(.white))
            } else {
                Spacer()
            }

            Text(message.displayText.isEmpty ? " " : message.displayText)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(message.role == .user
                    ? Color.accentColor
                    : Color(.secondarySystemBackground))
                .foregroundColor(message.role == .user ? .white : .primary)
                .cornerRadius(18)
                .frame(maxWidth: UIScreen.main.bounds.width * 0.75, alignment: message.role == .user ? .trailing : .leading)

            if message.role == .user {
                Circle()
                    .fill(Color(.systemGray4))
                    .frame(width: 28, height: 28)
                    .overlay(Image(systemName: "person.fill").font(.caption).foregroundColor(.secondary))
            } else {
                Spacer()
            }
        }
    }
}

// MARK: - Typing indicator

struct TypingIndicator: View {
    @State private var animating = false

    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<3) { i in
                Circle()
                    .fill(Color.secondary)
                    .frame(width: 8, height: 8)
                    .scaleEffect(animating ? 1 : 0.5)
                    .animation(.easeInOut(duration: 0.5).repeatForever().delay(Double(i) * 0.15), value: animating)
            }
        }
        .padding(12)
        .background(Color(.secondarySystemBackground))
        .cornerRadius(18)
        .onAppear { animating = true }
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
                    Label("Claude wants to write a file", systemImage: "pencil.circle.fill")
                        .font(.headline)

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Path").font(.caption.bold()).foregroundColor(.secondary)
                        Text(write.path).font(.system(.footnote, design: .monospaced))
                            .padding(8).background(Color(.secondarySystemBackground)).cornerRadius(8)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("Content preview").font(.caption.bold()).foregroundColor(.secondary)
                        Text(write.preview).font(.system(.footnote, design: .monospaced))
                            .padding(8).background(Color(.secondarySystemBackground)).cornerRadius(8)
                    }

                    Text("A backup will be saved at the same path with `.claudebackup` extension before writing.")
                        .font(.caption)
                        .foregroundColor(.secondary)
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
                    Button("Approve") { write.onApprove(); dismiss() }
                        .bold()
                }
            }
        }
    }
}

// MARK: - Helpers

private struct WriteWrapper: Identifiable {
    let id = UUID()
    let write: PendingWrite
    init(_ w: PendingWrite) { write = w }
}
