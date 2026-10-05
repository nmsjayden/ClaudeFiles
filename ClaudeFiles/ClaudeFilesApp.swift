import SwiftUI

@main
struct ClaudeFilesApp: App {
    @StateObject private var auth = AuthManager.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .onOpenURL { url in
                    auth.handleCallback(url: url)
                }
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
