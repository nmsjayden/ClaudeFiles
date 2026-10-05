import Foundation

/// Manages the FilzaJailedDS sandbox escape and SSV write bypass.
/// Call `activate()` once at app launch; it runs the kernel exploit
/// on a background thread so the UI is never blocked.
final class SandboxManager: ObservableObject {
    static let shared = SandboxManager()

    enum Status: Equatable {
        case idle
        case exploiting
        case escaped
        case failed(String)

        var description: String {
            switch self {
            case .idle:            return "Idle"
            case .exploiting:      return "Acquiring filesystem access…"
            case .escaped:         return "Full filesystem access active"
            case .failed(let msg): return "Sandbox escape failed: \(msg)"
            }
        }
    }

    @Published private(set) var status: Status = .idle

    private var activated = false
    private init() {}

    // MARK: - Public API

    /// Trigger the exploit once.  Safe to call multiple times; subsequent calls are no-ops.
    func activate() {
        guard !activated else { return }
        activated = true
        setStatus(.exploiting)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.runEscape()
        }
    }

    // MARK: - Exploit sequence

    private func runEscape() {
        DebugLog.log("[Sandbox] Starting kexploit_opa334…")

        // Step 1: kernel exploit
        let kret = kexploit_opa334()
        DebugLog.log("[Sandbox] kexploit_opa334 → \(kret)")
        guard kret == 0 else {
            setStatus(.failed("kexploit returned \(kret)"))
            return
        }

        // Step 2: escape the sandbox by rewriting kernel cr_label
        let selfProc = proc_self()
        DebugLog.log("[Sandbox] proc_self → 0x\(String(selfProc, radix: 16))")
        let sret = sandbox_escape(selfProc)
        DebugLog.log("[Sandbox] sandbox_escape → \(sret)")
        guard sret == 0 else {
            setStatus(.failed("sandbox_escape returned \(sret)"))
            return
        }

        // Step 3: patch the sandbox extension table so /System writes succeed
        let pret = patch_sandbox_ext()
        DebugLog.log("[Sandbox] patch_sandbox_ext → \(pret)")

        DebugLog.log("[Sandbox] Escape complete — full filesystem access active")
        setStatus(.escaped)
    }

    // MARK: - Helpers

    private func setStatus(_ s: Status) {
        DispatchQueue.main.async { self.status = s }
    }
}
