import SwiftUI
import AuthenticationServices

struct LoginView: View {
    @EnvironmentObject var authManager: AuthManager
    @State private var anchor: ASPresentationAnchor?

    var body: some View {
        VStack(spacing: 32) {
            Spacer()

            Image(systemName: "externaldrive.fill.badge.wifi")
                .font(.system(size: 64))
                .foregroundColor(.accentColor)

            VStack(spacing: 8) {
                Text("Claude Files")
                    .font(.largeTitle.bold())
                Text("Chat with Claude, read and write files via DarkSword")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            if authManager.isLoading {
                ProgressView("Logging in…")
            } else {
                Button(action: login) {
                    Label("Login with Claude", systemImage: "person.badge.key.fill")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.accentColor)
                        .foregroundColor(.white)
                        .cornerRadius(14)
                }
                .padding(.horizontal, 32)
            }

            if let err = authManager.errorMessage {
                Text(err)
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Spacer()

            Text("Uses your existing Claude.ai subscription\nNo extra API key needed")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.bottom, 32)
        }
        .background(
            // Capture the UIWindow for ASWebAuthenticationSession
            WindowReader { w in anchor = w }
        )
    }

    private func login() {
        guard let anchor else { return }
        authManager.startLogin(anchor: anchor)
    }
}

// MARK: - Window reader helper

private struct WindowReader: UIViewRepresentable {
    let onWindow: (UIWindow) -> Void

    func makeUIView(context: Context) -> UIView {
        let v = UIView()
        v.isHidden = true
        DispatchQueue.main.async {
            if let w = v.window { onWindow(w) }
        }
        return v
    }
    func updateUIView(_ uiView: UIView, context: Context) {
        DispatchQueue.main.async {
            if let w = uiView.window { onWindow(w) }
        }
    }
}
