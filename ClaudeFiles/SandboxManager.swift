import Foundation

/// Manages the FilzaJailedDS sandbox escape and SSV write bypass.
/// Call `activate()` once at app launch; it runs the kernel exploit
/// on a background DispatchQueue thread so the UI is never blocked.
@MainActor
final class SandboxManager: ObservableObject {
    static let shared = SandboxManager()

    enum Status: Equatable {
        case idle
        case exploiting
        case escaped
        case failed(String)

        var label: String {
            switch self {
            case .idle:              return "Idle"
            case .exploiting:        return "Acquiring filesystem access…"
            case .escaped:           return "Full filesystem access active"
            case .failed(let msg):   return "Sandbox escape failed: \(msg)"
            }
        }

        var isEscaped: Bool { if case .escaped = self { return true }; return false }
        var isFailed:  Bool { if case .failed  = self { return true }; return false }
    }

    @Published private(set) var status: Status = .idle
    private var activated = false

    private init() {}

    /// Trigger the exploit once. Safe to call multiple times; subsequent calls are no-ops.
    func activate() {
        guard !activated else { return }
        activated = true
        status = .exploiting
        // Use DispatchQueue (not Task.detached) to avoid Swift Concurrency
        // conflicts with @MainActor isolation on the static helper below.
        DispatchQueue.global(qos: .userInitiated).async {
            let result = SandboxManager.runEscape()
            DispatchQueue.main.async {
                SandboxManager.shared.status = result
            }
        }
    }

    // MARK: - Exploit sequence (runs off main thread via DispatchQueue)
    // Deliberately NOT @MainActor so it can run freely on the background queue.

    private static func runEscape() -> Status {
        DebugLog.log("[Sandbox] Starting kexploit_opa334…")

        let kret = kexploit_opa334()
        DebugLog.log("[Sandbox] kexploit_opa334 → \(kret)")
        guard kret == 0 else {
            return .failed("kexploit returned \(kret)")
        }

        let selfProc = proc_self()
        DebugLog.log("[Sandbox] proc_self → 0x\(String(selfProc, radix: 16))")
        let sret = sandbox_escape(selfProc)
        DebugLog.log("[Sandbox] sandbox_escape → \(sret)")
        guard sret == 0 else {
            return .failed("sandbox_escape returned \(sret)")
        }

        let pret = patch_sandbox_ext()
        DebugLog.log("[Sandbox] patch_sandbox_ext → \(pret)")
        DebugLog.log("[Sandbox] Escape complete ✓")
        return .escaped
    }
}
