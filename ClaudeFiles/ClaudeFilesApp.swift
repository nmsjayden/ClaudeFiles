import SwiftUI

@main
struct ClaudeFilesApp: App {
    @StateObject private var auth  = AuthManager.shared
    @StateObject private var store = ConversationStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .environmentObject(store)
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
