import SwiftUI

// MARK: - File browser entry point

struct FileBrowserView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var path: String = "/"
    @State private var history: [String] = ["/"]

    var body: some View {
        NavigationView {
            DirectoryView(path: path, onNavigate: navigateTo)
                .navigationTitle(displayTitle)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar { browserToolbar }
        }
    }

    private var displayTitle: String {
        if path == "/" { return "/" }
        return (path as NSString).lastPathComponent
    }

    @ToolbarContentBuilder
    private var browserToolbar: some ToolbarContent {
        ToolbarItem(placement: .cancellationAction) {
            Button("Done") { dismiss() }
        }
        ToolbarItem(placement: .navigationBarTrailing) {
            HStack(spacing: 16) {
                Button {
                    if history.count > 1 {
                        history.removeLast()
                        path = history.last ?? "/"
                    }
                } label: {
                    Image(systemName: "chevron.left")
                }
                .disabled(history.count <= 1)

                Button {
                    navigateTo((path as NSString).deletingLastPathComponent)
                } label: {
                    Image(systemName: "arrow.up")
                }
                .disabled(path == "/")
            }
        }
    }

    private func navigateTo(_ newPath: String) {
        path = newPath
        history.append(newPath)
    }
}

// MARK: - Directory listing

private struct DirectoryView: View {
    let path: String
    let onNavigate: (String) -> Void
    @State private var entries: [FileEntry] = []
    @State private var error: String?
    @State private var viewingFile: FileEntry?
    @State private var searchText = ""

    var body: some View {
        VStack(spacing: 0) {
            pathBar
            if let error {
                errorView(error)
            } else {
                fileList
            }
        }
        .onAppear { loadEntries() }
        .onChange(of: path) { _ in loadEntries() }
        .sheet(item: $viewingFile) { entry in
            FileViewerSheet(entry: entry)
        }
    }

    private var pathBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            Text(path)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 14)
                .padding(.vertical, 6)
        }
        .background(Color(.secondarySystemBackground))
    }

    private var fileList: some View {
        List {
            if !searchText.isEmpty {
                ForEach(filteredEntries) { entry in
                    FileRow(entry: entry) { tapped(entry) }
                }
            } else {
                ForEach(entries) { entry in
                    FileRow(entry: entry) { tapped(entry) }
                }
            }
        }
        .listStyle(.plain)
        .searchable(text: $searchText, prompt: "Filter files…")
    }

    private var filteredEntries: [FileEntry] {
        entries.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }

    private func tapped(_ entry: FileEntry) {
        if entry.isDirectory {
            onNavigate(entry.fullPath)
        } else {
            viewingFile = entry
        }
    }

    private func errorView(_ msg: String) -> some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text(msg)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            Button("Try /private\(path)") {
                onNavigate("/private" + path)
            }
            .font(.footnote)
            .opacity(path.hasPrefix("/var") || path.hasPrefix("/tmp") || path.hasPrefix("/etc") ? 1 : 0)
            Spacer()
        }
    }

    private func loadEntries() {
        let fm = FileManager.default
        error = nil
        entries = []

        do {
            let items = try fm.contentsOfDirectory(atPath: path)
            entries = items.sorted().map { name -> FileEntry in
                let full = (path as NSString).appendingPathComponent(name)
                var isDir: ObjCBool = false
                fm.fileExists(atPath: full, isDirectory: &isDir)
                let size = (try? fm.attributesOfItem(atPath: full)[.size] as? Int) ?? 0
                return FileEntry(name: name, fullPath: full, isDirectory: isDir.boolValue, size: size)
            }
        } catch {
            // Try POSIX fallback
            if let dir = opendir(path) {
                defer { closedir(dir) }
                var names: [String] = []
                while let entry = readdir(dir) {
                    let name = withUnsafePointer(to: entry.pointee.d_name) { ptr -> String in
                        ptr.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
                    }
                    if name == "." || name == ".." { continue }
                    names.append(name)
                }
                entries = names.sorted().map { name in
                    let full = (path as NSString).appendingPathComponent(name)
                    var isDir: ObjCBool = false
                    fm.fileExists(atPath: full, isDirectory: &isDir)
                    let size = (try? fm.attributesOfItem(atPath: full)[.size] as? Int) ?? 0
                    return FileEntry(name: name, fullPath: full, isDirectory: isDir.boolValue, size: size)
                }
            } else {
                self.error = "Cannot read directory: \(error.localizedDescription)"
            }
        }
    }
}

// MARK: - File row

private struct FileRow: View {
    let entry: FileEntry
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: entry.icon)
                    .font(.body)
                    .foregroundStyle(entry.iconColor)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(entry.name)
                        .font(.body)
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    if !entry.isDirectory {
                        Text(entry.formattedSize)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if entry.isDirectory {
                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - File viewer

private struct FileViewerSheet: View {
    let entry: FileEntry
    @Environment(\.dismiss) private var dismiss
    @State private var content: String = ""
    @State private var isLoading = true
    @State private var isBinary  = false
    @State private var copied    = false

    var body: some View {
        NavigationView {
            Group {
                if isLoading {
                    ProgressView("Loading…")
                } else if isBinary {
                    binaryView
                } else {
                    textView
                }
            }
            .navigationTitle(entry.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        UIPasteboard.general.string = content
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    }
                    .disabled(isBinary)
                }
            }
            .onAppear { loadFile() }
        }
    }

    private var textView: some View {
        ScrollView([.horizontal, .vertical]) {
            Text(content)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var binaryView: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "doc.questionmark")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Binary file")
                .font(.headline)
            Text(entry.formattedSize)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Text(content)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .padding()
            Spacer()
        }
    }

    private func loadFile() {
        DispatchQueue.global(qos: .userInitiated).async {
            let fm = FileManager.default
            guard let data = fm.contents(atPath: entry.fullPath) else {
                DispatchQueue.main.async {
                    content = "Cannot read file"
                    isLoading = false
                }
                return
            }

            if let text = String(data: data, encoding: .utf8) {
                let display = text.count > 100_000
                    ? String(text.prefix(100_000)) + "\n\n[Truncated — \(text.count) total chars]"
                    : text
                DispatchQueue.main.async {
                    content = display
                    isBinary = false
                    isLoading = false
                }
            } else {
                let hex = data.prefix(256).map { String(format: "%02x", $0) }
                    .enumerated()
                    .map { $0.offset > 0 && $0.offset % 16 == 0 ? "\n\($0.element)" : $0.element }
                    .joined(separator: " ")
                DispatchQueue.main.async {
                    content = hex
                    isBinary = true
                    isLoading = false
                }
            }
        }
    }
}

// MARK: - Model

struct FileEntry: Identifiable {
    let id = UUID()
    let name: String
    let fullPath: String
    let isDirectory: Bool
    let size: Int

    var formattedSize: String {
        if size < 1024 { return "\(size) B" }
        if size < 1_048_576 { return "\(size / 1024) KB" }
        return String(format: "%.1f MB", Double(size) / 1_048_576)
    }

    var icon: String {
        if isDirectory { return "folder.fill" }
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "plist":                         return "doc.badge.gearshape"
        case "json":                          return "curlybraces"
        case "xml":                           return "chevron.left.forwardslash.chevron.right"
        case "swift", "m", "h", "c", "cpp":  return "chevron.left.forwardslash.chevron.right"
        case "py", "rb", "js", "ts":          return "chevron.left.forwardslash.chevron.right"
        case "txt", "md", "log", "csv":       return "doc.text"
        case "png", "jpg", "jpeg", "gif", "heic": return "photo"
        case "mp4", "mov":                    return "film"
        case "mp3", "m4a", "wav", "aac":      return "waveform"
        case "zip", "tar", "gz":              return "doc.zipper"
        case "db", "sqlite", "sqlite3":       return "cylinder"
        case "dylib", "so", "framework":      return "shippingbox"
        default:                              return "doc"
        }
    }

    var iconColor: Color {
        if isDirectory { return .accentColor }
        let ext = (name as NSString).pathExtension.lowercased()
        switch ext {
        case "plist": return .orange
        case "json":  return .yellow
        case "swift": return .orange
        case "m", "h", "c", "cpp": return .blue
        case "py":    return .green
        case "js", "ts": return .yellow
        case "db", "sqlite", "sqlite3": return .purple
        default:      return .secondary
        }
    }
}
