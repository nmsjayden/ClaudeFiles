import SwiftUI
import AuthenticationServices

struct LoginView: View {
    @EnvironmentObject var auth: AuthManager
    @State private var windowScene: UIWindowScene?

    var body: some View {
        VStack(spacing: 32) {
            Spacer()

            Image(systemName: "externaldrive.fill.badge.wifi")
                .font(.system(size: 64)).foregroundColor(.accentColor)

            VStack(spacing: 8) {
                Text("Claude Files").font(.largeTitle.bold())
                Text("Chat with Claude · Read & write files via DarkSword")
                    .font(.subheadline).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).padding(.horizontal, 32)
            }

            if auth.isLoading {
                ProgressView("Signing in…")
            } else {
                Button(action: login) {
                    Label("Sign in with Claude", systemImage: "person.badge.key.fill")
                        .font(.headline).frame(maxWidth: .infinity)
                        .padding().background(Color.accentColor)
                        .foregroundColor(.white).cornerRadius(14)
                }
                .padding(.horizontal, 32)
            }

            if let err = auth.errorMessage {
                Text(err).font(.caption).foregroundColor(.red)
                    .multilineTextAlignment(.center).padding(.horizontal, 32)
            }

            Spacer()

            Text("Uses your existing Claude.ai subscription · No API key needed")
                .font(.caption).foregroundColor(.secondary)
                .multilineTextAlignment(.center).padding(.bottom, 32)
        }
        .background(SceneFinder { scene in windowScene = scene })
    }

    private func login() {
        guard let scene = windowScene,
              let window = scene.windows.first else { return }
        auth.startLogin(anchor: window)
    }
}

// MARK: - Scene finder (gets UIWindowScene without UIViewRepresentable UIWindow dependency)

private struct SceneFinder: UIViewRepresentable {
    let onScene: (UIWindowScene) -> Void

    func makeUIView(context: Context) -> UIView {
        let v = UIView(); v.isHidden = true; return v
    }
    func updateUIView(_ v: UIView, context: Context) {
        DispatchQueue.main.async {
            if let scene = v.window?.windowScene { onScene(scene) }
        }
    }
}
