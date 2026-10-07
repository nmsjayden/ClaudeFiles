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

/// Keeps API calls alive when the app goes to the background using two layers:
/// 1. Silent audio keepalive — plays inaudible audio so iOS treats the app
///    as actively playing media and never suspends it (technique from lara/rooootdev)
/// 2. UIKit background task — fallback that gives ~30s if audio session fails
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
        // Layer 1: Silent audio keepalive (indefinite background execution)
        KeepAliveManager.shared.activate()

        // Layer 2: UIKit background task (fallback, ~30s)
        guard backgroundTaskID == .invalid else { return }
        backgroundTaskID = UIApplication.shared.beginBackgroundTask(withName: "ClaudeAPICall") { [weak self] in
            self?.endBackgroundTask()
        }
        DebugLog.log("Background: keepalive + task started")
    }

    @objc private func appWillEnterForeground() {
        KeepAliveManager.shared.deactivate()
        endBackgroundTask()
    }

    private func endBackgroundTask() {
        guard backgroundTaskID != .invalid else { return }
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
