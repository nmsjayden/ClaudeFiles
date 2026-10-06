import SwiftUI
import UIKit

// MARK: - Entry point

struct ChatView: View {
    @EnvironmentObject var auth:    AuthManager
    @EnvironmentObject var store:   ConversationStore
    @EnvironmentObject var sandbox: SandboxManager
    @StateObject private var settings = SettingsStore.shared
    @State private var showingSidebar  = false
    @State private var showingSettings = false
    @State private var showingModels   = false
    @State private var showingBrowser  = false

    var body: some View {
        ChatContent(
            store: store, settings: settings, sandbox: sandbox,
            showingSidebar:  $showingSidebar,
            showingSettings: $showingSettings,
            showingModels:   $showingModels,
            showingBrowser:  $showingBrowser
        )
        .environmentObject(auth)
    }
}

// MARK: - Main screen

private struct ChatContent: View {
    @ObservedObject var store:    ConversationStore
    @ObservedObject var settings: SettingsStore
    @ObservedObject var sandbox:  SandboxManager
    @Binding var showingSidebar:  Bool
    @Binding var showingSettings: Bool
    @Binding var showingModels:   Bool
    @Binding var showingBrowser:  Bool
    @EnvironmentObject var auth: AuthManager
    @StateObject private var vm: ChatViewModel
    @FocusState private var inputFocused: Bool

    init(store: ConversationStore, settings: SettingsStore, sandbox: SandboxManager,
         showingSidebar: Binding<Bool>, showingSettings: Binding<Bool>,
         showingModels: Binding<Bool>, showingBrowser: Binding<Bool>) {
        self.store    = store
        self.settings = settings
        self.sandbox  = sandbox
        _showingSidebar  = showingSidebar
        _showingSettings = showingSettings
        _showingModels   = showingModels
        _showingBrowser  = showingBrowser
        _vm = StateObject(wrappedValue: ChatViewModel(store: store))
    }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                mainBody
                Divider().opacity(0.4)
                InputBar(vm: vm, inputFocused: _inputFocused)
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { toolbarContent }
        }
        .sheet(isPresented: $showingSidebar)  { ChatListSheet(store: store, isPresented: $showingSidebar) }
        .sheet(isPresented: $showingSettings) { SettingsSheet(settings: settings, sandbox: sandbox) }
        .sheet(isPresented: $showingModels)   { ModelPickerSheet(settings: settings) }
        .sheet(isPresented: $showingBrowser)  { FileBrowserView() }
        .sheet(item: $vm.pendingWrite)        { WriteApprovalSheet(write: $0) }
        .sheet(isPresented: errorBinding) {
            ErrorSheet(message: vm.error ?? "", onDismiss: { vm.error = nil })
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { vm.error != nil }, set: { if !$0 { vm.error = nil } })
    }

    @ViewBuilder
    private var mainBody: some View {
        if vm.displayMessages.isEmpty && !vm.isSending {
            EmptyStateView(sandbox: sandbox) { suggestion in
                vm.inputText = suggestion
                inputFocused = true
            }
            .contentShape(Rectangle())
            .onTapGesture { inputFocused = false }
        } else {
            MessageList(vm: vm, inputFocused: _inputFocused)
        }
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .navigationBarLeading) {
            Button {
                haptic(.light); showingSidebar = true
            } label: {
                Image(systemName: "line.3.horizontal").font(.body.weight(.medium))
            }
        }
        ToolbarItem(placement: .principal) {
            Button { haptic(.light); showingModels = true } label: {
                TitleStack(
                    title: store.selected?.title ?? "Chat",
                    model: settings.current,
                    sandboxColor: sandboxDotColor
                )
            }
            .buttonStyle(.plain)
        }
        ToolbarItem(placement: .navigationBarTrailing) {
            Menu {
                Button { haptic(.light); store.newConversation() } label: {
                    Label("New chat", systemImage: "square.and.pencil")
                }
                if !vm.displayMessages.isEmpty && !vm.isSending {
                    Button { vm.regenerateLast() } label: {
                        Label("Regenerate", systemImage: "arrow.clockwise")
                    }
                }
                Divider()
                Button { showingBrowser = true } label: {
                    Label("File browser", systemImage: "folder.badge.gearshape")
                }
                Button { showingModels = true } label: {
                    Label("Change model", systemImage: "cpu")
                }
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
        case .escaped:       return .green
        case .partial:       return .yellow
        case .exploiting:    return .orange
        case .failed:        return .red
        case .idle:          return .gray
        }
    }

    private func haptic(_ style: UIImpactFeedbackGenerator.FeedbackStyle) {
        UIImpactFeedbackGenerator(style: style).impactOccurred()
    }
}

// MARK: - Toolbar title

private struct TitleStack: View {
    let title: String
    let model: ModelOption
    let sandboxColor: Color

    var body: some View {
        VStack(spacing: 2) {
            Text(title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.primary)
                .lineLimit(1)
            HStack(spacing: 4) {
                Circle().fill(sandboxColor).frame(width: 5, height: 5)
                Text(model.shortName)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Image(systemName: "chevron.down")
                    .font(.system(size: 8, weight: .bold))
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: 220)
    }
}

// MARK: - Empty state

private struct EmptyStateView: View {
    let sandbox: SandboxManager
    let onSelect: (String) -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                Spacer().frame(height: 60)
                heroIcon
                Spacer().frame(height: 20)
                Text("What can I help with?").font(.title2.bold())
                sandboxLine.padding(.top, 6)
                Spacer().frame(height: 36)
                suggestionGrid
                Spacer().frame(height: 40)
            }
        }
    }

    private var heroIcon: some View {
        ZStack {
            Circle()
                .fill(LinearGradient(
                    colors: [Color.accentColor.opacity(0.18), Color.purple.opacity(0.10)],
                    startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: 80, height: 80)
            Image(systemName: "sparkles")
                .font(.system(size: 34, weight: .semibold))
                .foregroundStyle(LinearGradient(
                    colors: [Color.accentColor, Color.purple],
                    startPoint: .topLeading, endPoint: .bottomTrailing))
        }
    }

    private var sandboxLine: some View {
        let (text, color): (String, Color) = {
            switch sandbox.status {
            case .escaped:       return ("Full filesystem access active", .green)
            case .partial(let m): return (m, .yellow)
            case .exploiting(let s): return (s, .orange)
            case .failed(let m): return ("Sandbox escape failed · \(m)", .red)
            case .idle:          return ("Filesystem access pending", .gray)
            }
        }()
        return HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text).font(.footnote).foregroundStyle(.secondary)
        }
    }

    private var suggestionGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
            ForEach(Self.suggestions, id: \.text) { s in
                SuggestionChip(icon: s.icon, text: s.text) { onSelect(s.prompt) }
            }
        }
        .padding(.horizontal, 20)
    }

    private struct Suggestion { let icon, text, prompt: String }
    private static let suggestions: [Suggestion] = [
        .init(icon: "folder.badge.questionmark", text: "Explore /var/mobile",
              prompt: "List the contents of /var/mobile and tell me what's there"),
        .init(icon: "doc.text.magnifyingglass",  text: "Search for .plist files",
              prompt: "Search /var/mobile for .plist files, limit to the 20 most interesting"),
        .init(icon: "apps.iphone",               text: "Installed apps",
              prompt: "List everything in /var/containers/Bundle/Application and summarise what apps are installed"),
        .init(icon: "info.circle",               text: "System overview",
              prompt: "List /System and briefly describe what each top-level folder contains"),
    ]
}

private struct SuggestionChip: View {
    let icon:   String
    let text:   String
    let action: () -> Void

    var body: some View {
        Button {
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
            action()
        } label: {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(Color.accentColor)
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

// MARK: - Message list

private struct MessageList: View {
    @ObservedObject var vm: ChatViewModel
    @FocusState var inputFocused: Bool
    @State private var autoScroll: Bool = true
    @State private var bottomVisible: Bool = false

    var body: some View {
        ScrollViewReader { proxy in
            ZStack(alignment: .bottom) {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 18) {
                        ForEach(Array(vm.displayMessages.enumerated()), id: \.offset) { idx, msg in
                            MessageBubble(message: msg).id(idx)
                        }

                        if vm.isSending && vm.streamingBelongsToCurrentChat {
                            streamingContent
                        }

                        // Bottom anchor — uses onAppear/onDisappear to track visibility
                        Color.clear
                            .frame(height: 1)
                            .id("bottom")
                            .onAppear { bottomVisible = true; autoScroll = true }
                            .onDisappear { bottomVisible = false; autoScroll = false }
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 18)
                }
                .onChange(of: vm.displayMessages.count)    { _ in scrollIfAuto(proxy) }
                .onChange(of: vm.streamingText)            { _ in scrollIfAuto(proxy) }
                .onChange(of: vm.streamingToolCalls.count) { _ in scrollIfAuto(proxy) }
                .onChange(of: vm.isSending) { sending in
                    if sending {
                        autoScroll = true
                        scrollToBottom(proxy)
                    }
                }
                .scrollDismissesKeyboard(.interactively)
                .onTapGesture { inputFocused = false }

                // Jump-to-bottom button — visible when bottom anchor is off-screen
                if !bottomVisible {
                    Button {
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        autoScroll = true
                        withAnimation(.easeOut(duration: 0.25)) {
                            proxy.scrollTo("bottom", anchor: .bottom)
                        }
                    } label: {
                        Image(systemName: "arrow.down")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundStyle(.primary)
                            .frame(width: 36, height: 36)
                            .background(.ultraThinMaterial)
                            .clipShape(Circle())
                            .overlay(Circle().stroke(Color(.separator), lineWidth: 0.5))
                            .shadow(color: .black.opacity(0.15), radius: 6, y: 3)
                    }
                    .padding(.bottom, 12)
                    .transition(.scale(scale: 0.6).combined(with: .opacity))
                    .animation(.spring(response: 0.3, dampingFraction: 0.7), value: bottomVisible)
                }
            }
        }
    }

    @ViewBuilder
    private var streamingContent: some View {
        let liveTools = vm.streamingToolCalls.sorted(by: { $0.key < $1.key }).map(\.value)
        if !vm.streamingText.isEmpty || !liveTools.isEmpty {
            StreamingBubble(text: vm.streamingText, toolCalls: liveTools).id("streaming")
        } else {
            TypingBubble().id("typing")
        }
    }

    private func scrollIfAuto(_ proxy: ScrollViewProxy) {
        guard autoScroll else { return }
        scrollToBottom(proxy)
    }
    private func scrollToBottom(_ proxy: ScrollViewProxy) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.03) {
            withAnimation(.easeOut(duration: 0.15)) {
                proxy.scrollTo("bottom", anchor: .bottom)
            }
        }
    }
}

// MARK: - Input bar

private struct InputBar: View {
    @ObservedObject var vm: ChatViewModel
    @FocusState var inputFocused: Bool

    var body: some View {
        HStack(alignment: .bottom, spacing: 10) {
            textField
            actionButton
        }
        .padding(.horizontal, 12)
        .padding(.top, 10)
        .padding(.bottom, 12)
        .background(Color(.systemBackground))
    }

    private var textField: some View {
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
    }

    @ViewBuilder
    private var actionButton: some View {
        if vm.isSending {
            Button {
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                vm.stopGenerating()
            } label: {
                ZStack {
                    Circle().fill(Color.primary).frame(width: 36, height: 36)
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color(.systemBackground))
                        .frame(width: 12, height: 12)
                }
            }
        } else {
            Button {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                vm.send()
            } label: {
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
        }
    }
}

// MARK: - Bubbles

struct MessageBubble: View {
    let message: DisplayMessage

    var body: some View {
        if message.role == .user {
            userBubble
        } else {
            assistantBubble
        }
    }

    private var userBubble: some View {
        HStack {
            Spacer(minLength: 48)
            Text(message.text)
                .padding(.horizontal, 14).padding(.vertical, 10)
                .background(Color.accentColor)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 20))
                .textSelection(.enabled)
                .contextMenu {
                    Button {
                        UIPasteboard.general.string = message.text
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                }
        }
    }

    private var assistantBubble: some View {
        HStack(alignment: .top, spacing: 10) {
            AssistantAvatar()
            VStack(alignment: .leading, spacing: 8) {
                ForEach(message.toolCalls) { ToolCallCard(tool: $0) }
                if !message.text.isEmpty {
                    MarkdownView(message.text)
                        .textSelection(.enabled)
                        .contextMenu {
                            Button {
                                UIPasteboard.general.string = message.text
                            } label: {
                                Label("Copy text", systemImage: "doc.on.doc")
                            }
                        }
                }
            }
            Spacer(minLength: 0)
        }
    }
}

private struct AssistantAvatar: View {
    var body: some View {
        Circle()
            .fill(LinearGradient(
                colors: [Color.accentColor, Color.purple],
                startPoint: .topLeading, endPoint: .bottomTrailing))
            .frame(width: 28, height: 28)
            .overlay(
                Image(systemName: "sparkles")
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(.white))
    }
}

struct StreamingBubble: View {
    let text:      String
    let toolCalls: [ToolCallInfo]

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            AssistantAvatar()
            VStack(alignment: .leading, spacing: 8) {
                ForEach(toolCalls) { ToolCallCard(tool: $0) }
                if !text.isEmpty { MarkdownView(text) }
                if text.isEmpty && toolCalls.isEmpty { TypingIndicator() }
            }
            Spacer(minLength: 0)
        }
    }
}

private struct TypingBubble: View {
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            AssistantAvatar()
            TypingIndicator()
            Spacer()
        }
    }
}

// MARK: - Tool call card

struct ToolCallCard: View {
    let tool: ToolCallInfo
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerButton
            if expanded, tool.isComplete {
                Divider()
                expandedDetail
            }
        }
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color(.separator), lineWidth: 0.5))
    }

    private var headerButton: some View {
        Button {
            guard tool.isComplete else { return }
            withAnimation(.easeInOut(duration: 0.18)) { expanded.toggle() }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: iconName)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(tool.isComplete ? Color.accentColor : Color.orange)
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
    }

    private var expandedDetail: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !tool.input.isEmpty { inputSection }
            resultSection
        }
        .padding(12)
        .background(Color(.tertiarySystemBackground))
    }

    private var inputSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionLabel("INPUT")
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

    @ViewBuilder
    private var resultSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionLabel("RESULT")
            if let r = tool.result, !r.isEmpty {
                ScrollView {
                    Text(r)
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

    private var iconName: String {
        switch tool.name {
        case "read_file":      return "doc.text"
        case "write_file":     return "pencil.and.outline"
        case "list_directory": return "folder"
        case "search_files":   return "magnifyingglass"
        case "get_file_info":  return "info.circle"
        case "bash_exec":      return "terminal"
        case "grep_search":    return "text.magnifyingglass"
        case "head_file":      return "text.line.first.and.arrowtriangle.forward"
        case "tail_file":      return "text.line.last.and.arrowtriangle.forward"
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
        case "bash_exec":      return "Shell"
        case "grep_search":    return "Grep"
        case "head_file":      return "Head"
        case "tail_file":      return "Tail"
        default:               return tool.name
        }
    }
    private var pathArg: String? {
        tool.input["path"]?.string ?? tool.input["directory"]?.string ?? tool.input["command"]?.string
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

private struct SectionLabel: View {
    let text: String
    init(_ t: String) { text = t }
    var body: some View {
        Text(text)
            .font(.system(size: 9, weight: .bold))
            .foregroundStyle(.tertiary)
            .tracking(1)
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
                    .animation(
                        .easeInOut(duration: 0.55).repeatForever().delay(Double(i) * 0.15),
                        value: on)
            }
        }
        .padding(.vertical, 4)
        .onAppear { on = true }
    }
}

// MARK: - Model picker sheet

struct ModelPickerSheet: View {
    @ObservedObject var settings: SettingsStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    ForEach(ModelOption.grouped(), id: \.0) { family, models in
                        ModelFamilySection(
                            family: family,
                            models: models,
                            selectedId: settings.selectedModel,
                            onSelect: { opt in
                                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                                settings.select(opt)
                                dismiss()
                            })
                    }
                }
                .padding(16)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Choose model")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

private struct ModelFamilySection: View {
    let family:     ModelOption.Family
    let models:     [ModelOption]
    let selectedId: String
    let onSelect:   (ModelOption) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            VStack(spacing: 8) {
                ForEach(models) { m in
                    ModelCard(model: m, isSelected: m.id == selectedId) { onSelect(m) }
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: family.systemImage)
                .foregroundStyle(family.tint)
            Text(family.rawValue)
                .font(.headline)
            Spacer()
        }
        .padding(.horizontal, 4)
    }
}

private struct ModelCard: View {
    let model:      ModelOption
    let isSelected: Bool
    let action:     () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                leading
                VStack(alignment: .leading, spacing: 3) {
                    nameRow
                    Text(model.subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(Color.accentColor)
                        .font(.title3)
                }
            }
            .padding(14)
            .background(cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(borderColor, lineWidth: isSelected ? 1.5 : 0.5))
        }
        .buttonStyle(.plain)
    }

    private var leading: some View {
        ZStack {
            Circle()
                .fill(model.family.tint.opacity(0.15))
                .frame(width: 32, height: 32)
            Image(systemName: model.family.systemImage)
                .foregroundStyle(model.family.tint)
                .font(.system(size: 14, weight: .semibold))
        }
    }

    private var nameRow: some View {
        HStack(spacing: 6) {
            Text(model.displayName).font(.body.weight(.semibold)).foregroundStyle(.primary)
            if model.isRecommended {
                badge("DEFAULT", color: Color.accentColor)
            } else if model.isNewest {
                badge("NEW", color: .green)
            }
        }
    }

    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 8, weight: .heavy))
            .tracking(0.5)
            .foregroundStyle(color)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(color.opacity(0.15))
            .clipShape(Capsule())
    }

    private var cardBackground: Color {
        isSelected ? Color.accentColor.opacity(0.08) : Color(.secondarySystemBackground)
    }
    private var borderColor: Color {
        isSelected ? Color.accentColor : Color(.separator)
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
            ScrollView { content.padding() }
                .navigationTitle("Error")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { onDismiss(); dismiss() }
                    }
                }
        }
    }

    private var content: some View {
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
            copyButton
        }
    }

    private var copyButton: some View {
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
}

// MARK: - Chat list sheet

struct ChatListSheet: View {
    @ObservedObject var store: ConversationStore
    @Binding var isPresented: Bool
    @State private var renamingId: UUID?
    @State private var renameText  = ""
    @State private var deletingId: UUID?

    var body: some View {
        NavigationView {
            chatList
                .listStyle(.plain)
                .navigationTitle("Chats")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { chatToolbar }
                .alert("Rename chat", isPresented: renameBinding) { renameAlert }
                .alert("Delete chat?", isPresented: deleteBinding) { deleteAlert } message: {
                    Text("This cannot be undone.")
                }
        }
    }

    private var chatList: some View {
        List {
            ForEach(store.conversations) { c in
                ChatListRow(
                    conversation: c,
                    isSelected:   c.id == store.selectedId,
                    onSelect:     { store.selectedId = c.id; isPresented = false },
                    onRename:     { renamingId = c.id; renameText = c.title },
                    onDelete:     { deletingId = c.id })
            }
            .onDelete { offsets in
                if let idx = offsets.first {
                    deletingId = store.conversations[idx].id
                }
            }
        }
    }

    @ToolbarContentBuilder
    private var chatToolbar: some ToolbarContent {
        ToolbarItem(placement: .navigationBarLeading) { Button("Done") { isPresented = false } }
        ToolbarItem(placement: .navigationBarTrailing) {
            Button { store.newConversation(); isPresented = false } label: {
                Label("New", systemImage: "square.and.pencil").font(.body.weight(.medium))
            }
        }
    }

    private var renameBinding: Binding<Bool> {
        Binding(get: { renamingId != nil }, set: { if !$0 { renamingId = nil } })
    }
    private var deleteBinding: Binding<Bool> {
        Binding(get: { deletingId != nil }, set: { if !$0 { deletingId = nil } })
    }

    @ViewBuilder
    private var renameAlert: some View {
        TextField("Title", text: $renameText)
        Button("Cancel", role: .cancel) { renamingId = nil }
        Button("Save") {
            if let id = renamingId {
                store.rename(id, to: renameText.isEmpty ? "Untitled" : renameText)
            }
            renamingId = nil
        }
    }

    @ViewBuilder
    private var deleteAlert: some View {
        Button("Cancel", role: .cancel) { deletingId = nil }
        Button("Delete", role: .destructive) {
            if let id = deletingId { store.delete(id) }
            deletingId = nil
        }
    }
}

private struct ChatListRow: View {
    let conversation: Conversation
    let isSelected:   Bool
    let onSelect:     () -> Void
    let onRename:     () -> Void
    let onDelete:     () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Button(action: onSelect) { rowContent }.buttonStyle(.plain)
            menu
        }
        .padding(.vertical, 4)
    }

    private var rowContent: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(conversation.title).foregroundStyle(.primary).lineLimit(1)
                Text(conversation.updatedAt, style: .relative)
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if isSelected {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.accentColor)
            }
        }
        .contentShape(Rectangle())
    }

    private var menu: some View {
        Menu {
            Button(action: onRename) { Label("Rename", systemImage: "pencil") }
            Button(role: .destructive, action: onDelete) { Label("Delete", systemImage: "trash") }
        } label: {
            Image(systemName: "ellipsis.circle")
                .font(.title3).foregroundStyle(.secondary)
                .frame(width: 32, height: 32).contentShape(Rectangle())
        }
    }
}

// MARK: - Settings sheet

struct SettingsSheet: View {
    @ObservedObject var settings: SettingsStore
    @ObservedObject var sandbox:  SandboxManager
    @Environment(\.dismiss) private var dismiss
    @State private var showDebugLog   = false
    @State private var showModelPicker = false

    var body: some View {
        NavigationView {
            Form {
                modelSection
                permissionsSection
                appearanceSection
                sandboxSection
                aboutSection
                debugSection
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .sheet(isPresented: $showDebugLog)    { DebugLogSheet() }
            .sheet(isPresented: $showModelPicker) { ModelPickerSheet(settings: settings) }
        }
    }

    private var modelSection: some View {
        Section("Model") {
            Button { showModelPicker = true } label: {
                HStack(spacing: 12) {
                    ZStack {
                        Circle().fill(settings.current.family.tint.opacity(0.15))
                            .frame(width: 32, height: 32)
                        Image(systemName: settings.current.family.systemImage)
                            .foregroundStyle(settings.current.family.tint)
                            .font(.system(size: 14, weight: .semibold))
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(settings.current.displayName).foregroundStyle(.primary)
                        Text(settings.current.subtitle).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                }
            }
        }
    }

    private var permissionsSection: some View {
        Section {
            Toggle("Auto-approve file writes", isOn: $settings.autoApproveWrites)
            if settings.autoApproveWrites {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.caption)
                    Text("Claude will write files without asking. Backups are still created.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Permissions")
        } footer: {
            Text("When enabled, file writes are executed immediately without the approval dialog.")
        }
    }

    private var appearanceSection: some View {
        Section("Appearance") {
            Picker("Theme", selection: $settings.appTheme) {
                Text("System").tag("system")
                Text("Dark").tag("dark")
                Text("Light").tag("light")
            }
        }
    }

    private var sandboxSection: some View {
        Section("Filesystem") {
            HStack(spacing: 10) {
                Image(systemName: sandboxIcon).foregroundStyle(sandboxColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Sandbox escape").font(.body)
                    Text(sandbox.status.label).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
    }

    private var aboutSection: some View {
        Section("About") {
            HStack {
                Text("Version")
                Spacer()
                Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
                    .foregroundStyle(.secondary)
            }
            Link(destination: URL(string: "https://github.com/nmsjayden/ClaudeFiles")!) {
                HStack {
                    Label("Source on GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
                    Spacer()
                    Image(systemName: "arrow.up.right.square").foregroundStyle(.tertiary)
                }
            }
        }
    }

    private var debugSection: some View {
        Section("Debug") {
            Button { showDebugLog = true } label: {
                Label("View debug log", systemImage: "doc.text.magnifyingglass")
            }
            Button(role: .destructive) { DebugLog.clear() } label: {
                Label("Clear debug log", systemImage: "trash")
            }
        }
    }

    private var sandboxIcon: String {
        switch sandbox.status {
        case .escaped:       return "checkmark.shield.fill"
        case .partial:       return "exclamationmark.shield.fill"
        case .exploiting:    return "shield.lefthalf.filled"
        case .failed:        return "xmark.shield.fill"
        case .idle:          return "shield"
        }
    }
    private var sandboxColor: Color {
        switch sandbox.status {
        case .escaped:       return .green
        case .partial:       return .yellow
        case .exploiting:    return .orange
        case .failed:        return .red
        case .idle:          return .gray
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
            ScrollView { content.padding() }
                .navigationTitle("Write file")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { approvalToolbar }
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            InfoBlock(label: "PATH", value: write.path, mono: true)
            previewBlock
            Label("A `.claudebackup` copy is saved before writing.",
                  systemImage: "checkmark.shield.fill")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "pencil.circle.fill")
                .font(.title3).foregroundStyle(Color.accentColor)
            Text("Approve file write?").font(.headline)
            Spacer()
        }
    }

    private var previewBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel("CONTENT PREVIEW")
            ScrollView {
                Text(write.preview)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(maxHeight: 300)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    @ToolbarContentBuilder
    private var approvalToolbar: some ToolbarContent {
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

private struct InfoBlock: View {
    let label: String
    let value: String
    var mono  = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(label)
            Text(value)
                .font(mono ? .system(.footnote, design: .monospaced) : .footnote)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }
}

// (Preference key removed — scroll tracking now uses onAppear/onDisappear)
