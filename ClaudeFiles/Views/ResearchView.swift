import SwiftUI

// MARK: - Research View
// Runs kernel research commands directly — no AI, no API, no rate limits.

struct ResearchView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var runner = ResearchRunner()

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Command buttons
                ScrollView {
                    VStack(spacing: 12) {
                        headerCard

                        Section {
                            commandGroup(title: "Read-Only", icon: "magnifyingglass", color: .blue, commands: [
                                ("dump_self",        "Dump Self",          "Our proc/ucred/sandbox state"),
                                ("dump_proc",        "Dump launchd (1)",   "Launchd kernel state"),
                                ("compare",          "Compare to launchd", "Diff our creds vs PID 1"),
                                ("sandbox_ops",      "Sandbox Ops",        "Which operations are permitted"),
                                ("sandbox_profile",  "Sandbox Profile",    "Full sandbox_label dump"),
                                ("dump_extensions",  "Dump Extensions",    "All 16 extension buckets + class names"),
                                ("detect_zones",     "Detect Zones",       "Zone metadata exclusion range"),
                            ])
                        }

                        Section {
                            commandGroup(title: "Active Tests", icon: "bolt.fill", color: .orange, commands: [
                                ("patch_exec",    "Patch Exec (v6)",    "Redirect class_name ptr → sandbox.executable"),
                                ("swap_profile",  "Swap Profile",       "Copy SpringBoard's sandbox profile"),
                                ("exec_ext",      "Add Exec Extension", "Add process-exec sandbox ext"),
                                ("test_spawn",    "Test Spawn",         "posix_spawn after modifications"),
                            ])
                        }

                        Section {
                            commandGroup(title: "Logs", icon: "doc.text", color: .gray, commands: [
                                ("breadcrumbs",      "Research Log",     "kernel_research.m crash-safe log"),
                                ("ssv_breadcrumbs",  "SSV Log",          "sandbox.m escape crash-safe log"),
                            ])
                        }
                    }
                    .padding()
                }

                // Output area
                if runner.isRunning || !runner.output.isEmpty {
                    Divider()
                    outputSection
                }
            }
            .navigationTitle("Research")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { dismiss() } label: {
                        Image(systemName: "xmark")
                            .font(.body.weight(.medium))
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    if !runner.output.isEmpty {
                        Button {
                            UIPasteboard.general.string = runner.output
                            runner.copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                runner.copied = false
                            }
                        } label: {
                            Image(systemName: runner.copied ? "checkmark" : "doc.on.doc")
                                .font(.body.weight(.medium))
                        }
                    }
                }
            }
        }
    }

    // MARK: - Subviews

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: "cpu")
                    .font(.title2)
                    .foregroundColor(.purple)
                Text("Kernel Research Toolkit")
                    .font(.headline)
            }
            Text("Run commands directly on device. No AI, no API calls, no rate limits.")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(12)
    }

    private func commandGroup(title: String, icon: String, color: Color,
                               commands: [(id: String, label: String, desc: String)]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .foregroundColor(color)
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(.secondary)
            }
            .padding(.leading, 4)

            ForEach(commands, id: \.id) { cmd in
                Button {
                    runner.run(cmd.id)
                } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(cmd.label)
                                .font(.body.weight(.medium))
                                .foregroundColor(.primary)
                            Text(cmd.desc)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        if runner.isRunning && runner.currentCommand == cmd.id {
                            ProgressView()
                                .scaleEffect(0.8)
                        } else {
                            Image(systemName: "play.fill")
                                .font(.caption)
                                .foregroundColor(color)
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(Color(.tertiarySystemBackground))
                    .cornerRadius(10)
                }
                .disabled(runner.isRunning)
            }
        }
    }

    private var outputSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(runner.currentLabel)
                    .font(.caption.weight(.semibold))
                    .foregroundColor(.purple)
                Spacer()
                if runner.isRunning {
                    ProgressView()
                        .scaleEffect(0.7)
                }
                Text(runner.elapsed)
                    .font(.caption2.monospacedDigit())
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal)
            .padding(.top, 8)

            ScrollViewReader { proxy in
                ScrollView {
                    Text(runner.output.isEmpty ? "Running..." : runner.output)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.primary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal)
                        .id("outputEnd")
                }
                .frame(maxHeight: 300)
                .onChange(of: runner.output) { _ in
                    proxy.scrollTo("outputEnd", anchor: .bottom)
                }
            }

            Spacer().frame(height: 8)
        }
        .background(Color(.systemBackground))
    }
}

// MARK: - Runner
// Uses DispatchQueue.global() + autoreleasepool instead of Task.detached.
// The C functions in kernel_research.m use ObjC/Foundation internally
// (NSBundle, NSFileManager) and NEED an autorelease pool on non-main threads.

@MainActor
final class ResearchRunner: ObservableObject {
    @Published var output = ""
    @Published var isRunning = false
    @Published var currentCommand = ""
    @Published var currentLabel = ""
    @Published var copied = false
    @Published var elapsed = ""

    private var startTime: Date?
    private var timer: Timer?

    func run(_ command: String) {
        let labels: [String: String] = [
            "dump_self": "Dump Self",
            "dump_proc": "Dump launchd",
            "compare": "Compare Creds",
            "sandbox_ops": "Sandbox Ops",
            "sandbox_profile": "Sandbox Profile",
            "dump_extensions": "Dump Extensions",
            "detect_zones": "Detect Zones",
            "patch_exec": "Patch Exec v6",
            "swap_profile": "Swap Profile",
            "exec_ext": "Exec Extension",
            "test_spawn": "Test Spawn",
            "breadcrumbs": "Research Log",
            "ssv_breadcrumbs": "SSV Log",
        ]

        isRunning = true
        currentCommand = command
        currentLabel = labels[command] ?? command
        output = ""
        elapsed = "0.0s"
        startTime = Date()

        // Start elapsed timer
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            DispatchQueue.main.async { [weak self] in
                guard let self = self, let start = self.startTime else { return }
                let secs = Date().timeIntervalSince(start)
                self.elapsed = String(format: "%.1fs", secs)
            }
        }

        // Run on background GCD queue with autoreleasepool.
        // This is safer than Task.detached for calling ObjC/C functions
        // that internally create autorelease objects.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result: String = autoreleasepool {
                switch command {
                case "dump_self":
                    if let r = kresearch_dump_self() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED: exploit not initialized?" }

                case "dump_proc":
                    if let r = kresearch_dump_proc(1) {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED: could not dump PID 1" }

                case "compare":
                    if let r = kresearch_compare_creds(1) {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED: could not compare" }

                case "sandbox_ops":
                    if let r = kresearch_check_sandbox_ops() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "sandbox_profile":
                    if let r = kresearch_dump_sandbox_profile() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "swap_profile":
                    if let r = kresearch_swap_sandbox_profile() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "exec_ext":
                    if let r = kresearch_add_exec_extension() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "test_spawn":
                    if let r = kresearch_test_spawn() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "dump_extensions":
                    if let r = kresearch_dump_extensions() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "detect_zones":
                    if let r = kresearch_detect_zones() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "patch_exec":
                    if let r = kresearch_patch_exec() {
                        let s = String(cString: r); free(r); return s
                    } else { return "FAILED" }

                case "breadcrumbs":
                    if let r = kresearch_read_breadcrumbs() {
                        let s = String(cString: r); free(r); return s
                    } else { return "(no log file found)" }

                case "ssv_breadcrumbs":
                    if let r = read_ssv_breadcrumbs() {
                        let s = String(cString: r); free(r); return s
                    } else { return "(no SSV log file found)" }

                default:
                    return "Unknown command: \(command)"
                }
            }

            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.output = result
                self.isRunning = false
                self.timer?.invalidate()
                self.timer = nil
                if let start = self.startTime {
                    self.elapsed = String(format: "%.1fs", Date().timeIntervalSince(start))
                }
            }
        }
    }
}

// MARK: - Preview

struct ResearchView_Previews: PreviewProvider {
    static var previews: some View {
        ResearchView()
    }
}
