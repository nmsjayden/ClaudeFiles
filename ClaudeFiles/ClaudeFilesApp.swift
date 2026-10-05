import SwiftUI

@main
struct ClaudeFilesApp: App {
    @StateObject private var authManager = AuthManager.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(authManager)
                .onOpenURL { url in
                    authManager.handleCallback(url: url)
                }
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var authManager: AuthManager

    var body: some View {
        if authManager.isAuthenticated {
            ChatView()
        } else {
            LoginView()
        }
    }
}
