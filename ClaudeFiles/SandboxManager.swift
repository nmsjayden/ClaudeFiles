import Foundation

/// Manages the FilzaJailedDS sandbox escape and SSV write bypass.
/// Call `activate()` once at app launch. Runs on a background thread
/// with a watchdog timeout so the UI always gets a final status.
@MainActor
final class SandboxManager: ObservableObject {
    static let shared = SandboxManager()

    enum Status: Equatable {
        case idle
        case exploiting(String)   // substep description
        case escaped
        case partial(String)      // exploit ran but escape/patch failed — app still usable for sandbox-accessible paths
        case failed(String)

        var label: String {
            switch self {
            case .idle:              return "Idle"
            case .exploiting(let s): return s
            case .escaped:           return "Full filesystem access active"
            case .partial(let s):    return "Partial access — \(s)"
            case .failed(let msg):   return "Failed: \(msg)"
            }
        }

        var isEscaped: Bool  { if case .escaped  = self { return true }; return false }
        var isPartial: Bool  { if case .partial  = self { return true }; return false }
        var isFailed:  Bool  { if case .failed   = self { return true }; return false }
        var isWorking: Bool  { if case .exploiting = self { return true }; return false }
        /// App is usable (can at least try file ops)
        var isUsable:  Bool  { isEscaped || isPartial }
    }

    @Published private(set) var status: Status = .idle
    private var activated = false

    private init() {}

    func activate() {
        guard !activated else { return }
        activated = true
        status = .exploiting("Starting kernel exploit…")

        // Watchdog: if the background thread doesn't report back in 15s,
        // assume it crashed and mark partial access.
        let watchdog = DispatchWorkItem { [weak self] in
            guard let self else { return }
            Task { @MainActor in
                if self.status.isWorking {
                    DebugLog.log("[Sandbox] Watchdog: exploit thread timed out after 15s")
                    self.status = .partial("exploit thread timed out — sandbox escape may have crashed")
                }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 15, execute: watchdog)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = SandboxManager.runEscape { step in
                DispatchQueue.main.async {
                    self?.status = .exploiting(step)
                }
            }
            watchdog.cancel()
            DispatchQueue.main.async {
                self?.status = result
            }
        }
    }

    // MARK: - Exploit sequence (background thread)

    private nonisolated static func runEscape(progress: @escaping (String) -> Void) -> Status {
        // Step 1: kernel exploit
        DebugLog.log("[Sandbox] Starting kexploit_opa334…")
        progress("Running kernel exploit…")
        let kret = kexploit_opa334()
        DebugLog.log("[Sandbox] kexploit_opa334 → \(kret)")
        guard kret == 0 else {
            return .failed("kexploit returned \(kret)")
        }

        // Step 2: get our proc
        progress("Resolving process…")
        let selfProc = proc_self()
        DebugLog.log("[Sandbox] proc_self → 0x\(String(selfProc, radix: 16))")
        guard selfProc != 0 else {
            return .failed("proc_self returned NULL")
        }

        // Step 3: escape sandbox — this is the dangerous call that may crash
        DebugLog.log("[Sandbox] Calling sandbox_escape(0x\(String(selfProc, radix: 16)))…")
        progress("Escaping sandbox…")
        let sret = sandbox_escape(selfProc)
        DebugLog.log("[Sandbox] sandbox_escape → \(sret)")
        guard sret == 0 else {
            return .partial("sandbox_escape returned \(sret) — kernel exploit succeeded but sandbox not fully escaped")
        }

        // Signal that the exploit + escape succeeded so patch_sandbox_ext
        // knows kernel R/W is available (mirrors what Tweak.m did).
        set_exploit_done()
        DebugLog.log("[Sandbox] g_exploitDone set to true")

        // Step 4: patch sandbox extensions for SSV-protected writes
        DebugLog.log("[Sandbox] Calling patch_sandbox_ext…")
        progress("Patching sandbox extensions…")
        let pret = patch_sandbox_ext()
        DebugLog.log("[Sandbox] patch_sandbox_ext → \(pret)")

        if pret != 0 {
            DebugLog.log("[Sandbox] patch_sandbox_ext failed but sandbox_escape succeeded — partial access")
            return .partial("sandbox escaped but SSV patch failed (\(pret)) — /var access likely works, /System may not")
        }

        DebugLog.log("[Sandbox] Escape complete ✓")
        return .escaped
    }
}
