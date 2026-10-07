import SwiftUI
import UIKit

@main
struct ClaudeFilesApp: App {
    @StateObject private var auth    = AuthManager.shared
    @StateObject private var store   = ConversationStore()
    @StateObject private var sandbox = SandboxManager.shared
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    init() {
        // Kick off the kernel exploit + sandbox escape immediately, before first frame.
        // Runs on a background thread — UI is never blocked.
        SandboxManager.shared.activate()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .environmentObject(store)
                .environmentObject(sandbox)
        }
    }
}

// MARK: - Background execution support

/// Keeps API calls alive when the app goes to the background.
/// Uses a UIKit background task to request extra execution time from iOS,
/// so streaming responses and tool loops finish instead of being killed.
class AppDelegate: NSObject, UIApplicationDelegate {
    private var backgroundTaskID: UIBackgroundTaskIdentifier = .invalid

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        NotificationCenter.default.addObserver(
            self, selector: #selector(appDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification, object: nil)
        NotificationCenter.default.addObserver(
            self, selector: #selector(appWillEnterForeground),
            name: UIApplication.willEnterForegroundNotification, object: nil)
        return true
    }

    @objc private func appDidEnterBackground() {
        // Request background execution time (up to ~30s, sometimes more)
        guard backgroundTaskID == .invalid else { return }
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "ClaudeAPICall") { [weak self] in
            // Expiration handler — system is about to kill us, end gracefully
            self?.endBackgroundTask()
        }
        DebugLog.log("Background task started (id: \(backgroundTaskID.rawValue))")
    }

    @objc private func appWillEnterForeground() {
        endBackgroundTask()
    }

    private func endBackgroundTask() {
        guard backgroundTaskID != .invalid else { return }
        DebugLog.log("Background task ended (id: \(backgroundTaskID.rawValue))")
        UIApplication.shared.endBackgroundTask(backgroundTaskID)
        backgroundTaskID = .invalid
    }
}

struct ContentView: View {
    @EnvironmentObject var auth: AuthManager
    @ObservedObject private var settings = SettingsStore.shared

    var body: some View {
        Group {
            if auth.isAuthenticated {
                ChatView()
            } else {
                LoginView()
            }
        }
        .preferredColorScheme(colorScheme)
    }

    private var colorScheme: ColorScheme? {
        switch settings.appTheme {
        case "dark":  return .dark
        case "light": return .light
        default:      return nil  // system
        }
    }
}
