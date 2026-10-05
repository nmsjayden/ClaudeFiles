import SwiftUI
import AuthenticationServices

struct LoginView: View {
    @EnvironmentObject var auth: AuthManager
    @State private var scene: UIWindowScene?
    @State private var codeText: String = ""

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "externaldrive.fill.badge.wifi")
                .font(.system(size: 64)).foregroundColor(.accentColor)

            VStack(spacing: 8) {
                Text("Claude Files").font(.largeTitle.bold())
                Text("Chat with Claude · Read & write files via DarkSword")
                    .font(.subheadline).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).padding(.horizontal, 32)
            }

            if auth.awaitingCode {
                codeEntry
            } else if auth.isLoading {
                ProgressView("Opening Claude.ai…")
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

            Text("Uses your Claude.ai account · OAuth via Claude Code's flow")
                .font(.caption2).foregroundColor(.secondary)
                .multilineTextAlignment(.center).padding(.bottom, 24)
        }
        .background(SceneFinder { s in scene = s })
    }

    // MARK: - Paste code UI

    private var codeEntry: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste the authorization code")
                .font(.headline)
            Text("After clicking **Authorize** on claude.ai, you'll see a page with a code. Copy it and paste it below.")
                .font(.caption).foregroundColor(.secondary)

            TextField("Paste code here", text: $codeText, axis: .vertical)
                .lineLimit(2...4)
                .padding(10)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(10)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

            HStack {
                Button("Cancel") {
                    codeText = ""
                    auth.cancelCodeEntry()
                }
                .foregroundColor(.red)

                Spacer()

                Button {
                    auth.submitCode(codeText)
                    codeText = ""
                } label: {
                    Text("Submit").bold()
                        .padding(.horizontal, 20).padding(.vertical, 10)
                        .background(Color.accentColor)
                        .foregroundColor(.white).cornerRadius(10)
                }
                .disabled(codeText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(.horizontal, 32)
    }

    private func login() {
        guard let scene, let window = scene.windows.first else { return }
        auth.startLogin(anchor: window)
    }
}

private struct SceneFinder: UIViewRepresentable {
    let onScene: (UIWindowScene) -> Void
    func makeUIView(context: Context) -> UIView {
        let v = UIView(); v.isHidden = true; return v
    }
    func updateUIView(_ v: UIView, context: Context) {
        DispatchQueue.main.async {
            if let s = v.window?.windowScene { onScene(s) }
        }
    }
}
