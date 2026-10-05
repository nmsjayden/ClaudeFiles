import SwiftUI
import AuthenticationServices

struct LoginView: View {
    @EnvironmentObject var auth:    AuthManager
    @EnvironmentObject var sandbox: SandboxManager
    @State private var scene: UIWindowScene?
    @State private var codeText: String = ""

    var body: some View {
        ZStack {
            // Dark gradient background
            LinearGradient(colors: [Color(red: 0.07, green: 0.07, blue: 0.18),
                                     Color(red: 0.12, green: 0.06, blue: 0.26)],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
                .ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer()

                // Icon + title
                VStack(spacing: 20) {
                    ZStack {
                        Circle()
                            .fill(LinearGradient(colors: [Color(red: 0.55, green: 0.34, blue: 0.89),
                                                           Color(red: 0.38, green: 0.18, blue: 0.72)],
                                                  startPoint: .topLeading, endPoint: .bottomTrailing))
                            .frame(width: 90, height: 90)
                            .shadow(color: Color(red: 0.55, green: 0.34, blue: 0.89).opacity(0.5),
                                    radius: 20, y: 8)

                        Image(systemName: "sparkles")
                            .font(.system(size: 38, weight: .semibold))
                            .foregroundStyle(.white)
                    }

                    VStack(spacing: 8) {
                        Text("Claude Files")
                            .font(.system(size: 32, weight: .bold))
                            .foregroundStyle(.white)

                        Text("Full filesystem access · Powered by Claude")
                            .font(.subheadline)
                            .foregroundStyle(.white.opacity(0.6))
                            .multilineTextAlignment(.center)
                    }
                }

                Spacer().frame(height: 48)

                // Auth card
                VStack(spacing: 16) {
                    if auth.awaitingCode {
                        codeEntry
                    } else if auth.isLoading {
                        HStack(spacing: 10) {
                            ProgressView().tint(.white)
                            Text("Opening Claude.ai…")
                                .foregroundStyle(.white.opacity(0.8))
                        }
                        .padding(.vertical, 8)
                    } else {
                        Button(action: login) {
                            HStack(spacing: 10) {
                                Image(systemName: "person.badge.key.fill")
                                Text("Sign in with Claude")
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 16)
                            .background(Color.accentColor)
                            .foregroundStyle(.white)
                            .clipShape(RoundedRectangle(cornerRadius: 16))
                        }
                    }

                    if let err = auth.errorMessage {
                        Text(err)
                            .font(.caption)
                            .foregroundStyle(Color.red.opacity(0.9))
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 8)
                    }
                }
                .padding(24)
                .background(.ultraThinMaterial.opacity(0.6))
                .clipShape(RoundedRectangle(cornerRadius: 24))
                .padding(.horizontal, 24)

                Spacer()

                // Sandbox status
                sandboxStatus
                    .padding(.bottom, 32)
            }
        }
        .background(SceneFinder { s in scene = s })
    }

    // MARK: - Sandbox badge

    private var sandboxStatus: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(statusColor)
                .frame(width: 7, height: 7)
                .overlay(
                    Circle()
                        .fill(statusColor.opacity(0.4))
                        .frame(width: 14, height: 14)
                        .opacity(sandbox.status.isWorking ? 1 : 0)
                        .scaleEffect(sandbox.status.isWorking ? 1.4 : 1)
                        .animation(.easeInOut(duration: 1).repeatForever(autoreverses: true),
                                   value: sandbox.status.isWorking)
                )
            Text(sandbox.status.label)
                .font(.caption2)
                .foregroundStyle(.white.opacity(0.5))
        }
    }

    private var statusColor: Color {
        switch sandbox.status {
        case .idle:          return .gray
        case .exploiting:    return .orange
        case .escaped:       return .green
        case .partial:       return .yellow
        case .failed:        return .red
        }
    }

    // MARK: - Code paste UI

    private var codeEntry: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste the authorization code")
                .font(.headline)
                .foregroundStyle(.white)

            Text("After tapping **Authorize** on claude.ai, copy the code shown and paste it below.")
                .font(.caption)
                .foregroundStyle(.white.opacity(0.6))

            TextField("Paste code here", text: $codeText, axis: .vertical)
                .lineLimit(2...4)
                .padding(12)
                .background(Color.white.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 10))
                .foregroundStyle(.white)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

            HStack {
                Button("Cancel") {
                    codeText = ""
                    auth.cancelCodeEntry()
                }
                .foregroundStyle(.red.opacity(0.9))

                Spacer()

                Button {
                    auth.submitCode(codeText)
                    codeText = ""
                } label: {
                    Text("Submit")
                        .bold()
                        .padding(.horizontal, 24)
                        .padding(.vertical, 10)
                        .background(Color.accentColor)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .disabled(codeText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
    }

    private func login() {
        guard let scene, let window = scene.windows.first else { return }
        auth.startLogin(anchor: window)
    }
}

private struct SceneFinder: UIViewRepresentable {
    let onScene: (UIWindowScene) -> Void
    func makeUIView(context: Context) -> UIView { let v = UIView(); v.isHidden = true; return v }
    func updateUIView(_ v: UIView, context: Context) {
        DispatchQueue.main.async { if let s = v.window?.windowScene { onScene(s) } }
    }
}
