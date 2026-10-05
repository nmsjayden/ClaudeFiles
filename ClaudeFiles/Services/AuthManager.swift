import Foundation
import AuthenticationServices
import CryptoKit
import Security

@MainActor
final class AuthManager: NSObject, ObservableObject {
    static let shared = AuthManager()

    @Published var isAuthenticated = false
    @Published var isLoading = false
    @Published var errorMessage: String?

    // Claude Code's public OAuth client — same one the CLI uses
    private let clientId    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    private let authorizeURL = "https://claude.ai/oauth/authorize"
    private let tokenURL    = "https://console.anthropic.com/v1/oauth/token"
    private let refreshURL  = "https://console.anthropic.com/v1/oauth/token"
    private let scopes      = "org:create_api_key user:profile user:inference"
    private let redirectURI  = "claudefiles://oauth/callback"

    private var pendingVerifier: String?
    private var pendingState: String?
    private var authSession: ASWebAuthenticationSession?

    private override init() {
        super.init()
        isAuthenticated = (keychainLoad("access_token") != nil)
    }

    // MARK: - Start login

    func startLogin(anchor: ASPresentationAnchor) {
        isLoading = true
        errorMessage = nil

        let verifier  = pkceVerifier()
        let challenge = pkceChallenge(verifier)
        let state     = randomBase64(16)

        pendingVerifier = verifier
        pendingState    = state

        var c = URLComponents(string: authorizeURL)!
        c.queryItems = [
            .init(name: "client_id",             value: clientId),
            .init(name: "response_type",          value: "code"),
            .init(name: "redirect_uri",           value: redirectURI),
            .init(name: "scope",                  value: scopes),
            .init(name: "code_challenge",         value: challenge),
            .init(name: "code_challenge_method",  value: "S256"),
            .init(name: "state",                  value: state),
        ]
        guard let url = c.url else { isLoading = false; return }

        let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "claudefiles") { [weak self] cb, err in
            Task { @MainActor [weak self] in self?.handleCallback(url: cb, error: err) }
        }
        session.presentationContextProvider = WindowAnchorProvider(anchor: anchor)
        session.prefersEphemeralWebBrowserSession = false
        session.start()
        authSession = session
    }

    // MARK: - Handle redirect

    func handleCallback(url: URL?, error: Error? = nil) {
        defer { isLoading = false }

        if let err = error as? ASWebAuthenticationSessionError, err.code == .canceledLogin { return }
        if let err = error { errorMessage = err.localizedDescription; return }

        guard
            let url       = url,
            let comps     = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let code      = comps.queryItems?.first(where: { $0.name == "code" })?.value,
            let retState  = comps.queryItems?.first(where: { $0.name == "state" })?.value,
            retState      == pendingState,
            let verifier  = pendingVerifier
        else { errorMessage = "OAuth callback invalid"; return }

        Task { await exchange(code: code, verifier: verifier) }
    }

    // MARK: - Exchange code for tokens

    private func exchange(code: String, verifier: String) async {
        var req = URLRequest(url: URL(string: tokenURL)!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONEncoder().encode([
            "grant_type":    "authorization_code",
            "client_id":     clientId,
            "code":          code,
            "redirect_uri":  redirectURI,
            "code_verifier": verifier,
        ])

        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let tok = try JSONDecoder().decode(TokenResponse.self, from: data)
            keychainSave("access_token",  tok.accessToken)
            if let r = tok.refreshToken { keychainSave("refresh_token", r) }
            if let e = tok.expiresIn {
                let exp = Date().addingTimeInterval(TimeInterval(e))
                keychainSave("token_expiry", ISO8601DateFormatter().string(from: exp))
            }
            isAuthenticated = true
        } catch {
            errorMessage = "Token exchange failed: \(error.localizedDescription)"
        }
        isLoading = false
    }

    // MARK: - Get valid access token (auto-refresh)

    func accessToken() async -> String? {
        guard let token = keychainLoad("access_token") else { return nil }

        // Check expiry — refresh if within 60 s
        if let expStr = keychainLoad("token_expiry"),
           let exp    = ISO8601DateFormatter().date(from: expStr),
           Date().addingTimeInterval(60) >= exp,
           let refresh = keychainLoad("refresh_token") {
            return await doRefresh(refreshToken: refresh) ?? token
        }
        return token
    }

    private func doRefresh(refreshToken: String) async -> String? {
        var req = URLRequest(url: URL(string: refreshURL)!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONEncoder().encode([
            "grant_type":    "refresh_token",
            "client_id":     clientId,
            "refresh_token": refreshToken,
        ])
        guard
            let (data, _) = try? await URLSession.shared.data(for: req),
            let tok = try? JSONDecoder().decode(TokenResponse.self, from: data)
        else { return nil }

        keychainSave("access_token", tok.accessToken)
        if let r = tok.refreshToken { keychainSave("refresh_token", r) }
        if let e = tok.expiresIn {
            let exp = Date().addingTimeInterval(TimeInterval(e))
            keychainSave("token_expiry", ISO8601DateFormatter().string(from: exp))
        }
        return tok.accessToken
    }

    // MARK: - Logout

    func logout() {
        for k in ["access_token", "refresh_token", "token_expiry"] { keychainDelete(k) }
        isAuthenticated = false
    }

    // MARK: - Keychain helpers

    private func keychainSave(_ key: String, _ value: String) {
        let data = Data(value.utf8)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                 kSecAttrService as String: "ClaudeFiles",
                                 kSecAttrAccount as String: key]
        SecItemDelete(q as CFDictionary)
        var add = q; add[kSecValueData as String] = data
        SecItemAdd(add as CFDictionary, nil)
    }

    private func keychainLoad(_ key: String) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                 kSecAttrService as String: "ClaudeFiles",
                                 kSecAttrAccount as String: key,
                                 kSecReturnData as String: true]
        var result: AnyObject?
        SecItemCopyMatching(q as CFDictionary, &result)
        guard let d = result as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    private func keychainDelete(_ key: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                 kSecAttrService as String: "ClaudeFiles",
                                 kSecAttrAccount as String: key]
        SecItemDelete(q as CFDictionary)
    }

    // MARK: - PKCE

    private func pkceVerifier() -> String { randomBase64(32) }

    private func pkceChallenge(_ verifier: String) -> String {
        Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncoded()
    }

    private func randomBase64(_ byteCount: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        return Data(bytes).base64URLEncoded()
    }
}

// MARK: - ASWebAuthentication anchor wrapper

private final class WindowAnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    let anchor: ASPresentationAnchor
    init(anchor: ASPresentationAnchor) { self.anchor = anchor }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchor }
}

// MARK: - Models

private struct TokenResponse: Decodable {
    let accessToken:  String
    let refreshToken: String?
    let expiresIn:    Int?
    enum CodingKeys: String, CodingKey {
        case accessToken  = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn    = "expires_in"
    }
}

private extension Data {
    func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
