import SwiftUI

@main
struct ClaudeFilesApp: App {
    @StateObject private var auth    = AuthManager.shared
    @StateObject private var store   = ConversationStore()
    @StateObject private var sandbox = SandboxManager.shared

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
