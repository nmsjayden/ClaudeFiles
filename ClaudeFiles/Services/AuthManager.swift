import Foundation
import AuthenticationServices
import CryptoKit
import Security

@MainActor
final class AuthManager: NSObject, ObservableObject {
    static let shared = AuthManager()

    @Published var isAuthenticated = false
    @Published var isLoading       = false
    @Published var errorMessage:   String?
    @Published var awaitingCode    = false   // show paste field after Safari closes

    private let clientId     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    private let authorizeURL = "https://claude.ai/oauth/authorize"
    private let tokenURL     = "https://console.anthropic.com/v1/oauth/token"
    private let scopes       = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
    // Claude Code's registered callback — the page displays the code for the user to paste.
    private let redirectURI  = "https://console.anthropic.com/oauth/code/callback"

    private var pendingVerifier: String?
    private var pendingState:    String?
    private var authSession:     ASWebAuthenticationSession?
    private var anchorProvider:  AnchorProvider?

    private override init() {
        super.init()
        isAuthenticated = (keychainLoad("access_token") != nil)
    }

    // MARK: - Start login (opens Safari to Claude.ai → shows code on page)

    func startLogin(anchor: ASPresentationAnchor) {
        // Reset ALL state from any previous attempt
        isLoading    = true
        errorMessage = nil
        awaitingCode = false
        authSession?.cancel()
        authSession  = nil

        // Clear any stale tokens from a revoked session
        keychainDelete("access_token")
        keychainDelete("refresh_token")

        let verifier  = randomBase64(32)
        let challenge = pkceChallenge(verifier)
        // Claude Code uses the verifier itself as the state parameter
        let state     = verifier
        pendingVerifier = verifier
        pendingState    = state

        var c = URLComponents(string: authorizeURL)!
        c.queryItems = [
            .init(name: "code",                 value: "true"),
            .init(name: "client_id",            value: clientId),
            .init(name: "response_type",         value: "code"),
            .init(name: "redirect_uri",          value: redirectURI),
            .init(name: "scope",                 value: scopes),
            .init(name: "code_challenge",        value: challenge),
            .init(name: "code_challenge_method", value: "S256"),
            .init(name: "state",                 value: state),
        ]
        guard let url = c.url else {
            isLoading = false
            errorMessage = "Failed to build OAuth URL"
            return
        }

        DebugLog.log("[Auth] Opening OAuth: \(url.absoluteString.prefix(120))…")

        let provider = AnchorProvider(anchor: anchor)
        anchorProvider = provider

        // Using "https" callback scheme so we DON'T intercept — user copies the code from page.
        // Session will stay open; the user closes it after copying the code.
        let session = ASWebAuthenticationSession(
            url: url,
            callbackURLScheme: nil
        ) { [weak self] callbackURL, error in
            Task { @MainActor [weak self] in
                if let error {
                    DebugLog.log("[Auth] ASWebAuth completed with error: \(error.localizedDescription)")
                }
                self?.isLoading = false
                self?.awaitingCode = true   // show paste UI
            }
        }
        session.presentationContextProvider = provider
        session.prefersEphemeralWebBrowserSession = false

        let started = session.start()
        DebugLog.log("[Auth] ASWebAuthenticationSession.start() → \(started)")

        if !started {
            isLoading = false
            errorMessage = "Could not open sign-in page. Try again."
            return
        }
        authSession = session
    }

    // MARK: - User pastes the code

    func submitCode(_ raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { errorMessage = "Code is empty"; return }

        // Claude Code's callback page shows the code as "<code>#<state>" sometimes
        let parts = trimmed.split(separator: "#", maxSplits: 1).map(String.init)
        let code  = parts[0]

        guard let verifier = pendingVerifier else {
            errorMessage = "No pending login. Try again."
            return
        }

        isLoading    = true
        awaitingCode = false
        Task { await exchange(code: code, verifier: verifier) }
    }

    func cancelCodeEntry() {
        awaitingCode = false
        pendingVerifier = nil
        pendingState = nil
    }

    // MARK: - Token exchange

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
            "state":         pendingState ?? "",
        ])

        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
                let msg = String(data: data, encoding: .utf8) ?? "HTTP \(http.statusCode)"
                errorMessage = "Token exchange failed: \(msg.prefix(200))"
                isLoading = false
                return
            }
            let tok = try JSONDecoder().decode(TokenResponse.self, from: data)
            keychainSave("access_token", tok.accessToken)
            if let r = tok.refreshToken { keychainSave("refresh_token", r) }
            isAuthenticated = true
        } catch {
            errorMessage = "Sign-in failed: \(error.localizedDescription)"
        }
        isLoading = false
    }

    func accessToken() async -> String? { keychainLoad("access_token") }

    /// Attempt to refresh the access token using the stored refresh token.
    /// Returns the new access token on success, nil on failure (user must re-login).
    func refreshAccessToken() async -> String? {
        guard let refreshToken = keychainLoad("refresh_token") else {
            DebugLog.log("[Auth] No refresh token stored — user must re-login")
            return nil
        }

        DebugLog.log("[Auth] Refreshing access token…")
        var req = URLRequest(url: URL(string: tokenURL)!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONEncoder().encode([
            "grant_type":    "refresh_token",
            "client_id":     clientId,
            "refresh_token": refreshToken,
        ])

        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
                let msg = String(data: data, encoding: .utf8) ?? "HTTP \(http.statusCode)"
                DebugLog.log("[Auth] Refresh failed: \(msg.prefix(300))")
                // Refresh token is also expired/invalid — clear everything and force re-login
                for k in ["access_token", "refresh_token"] { keychainDelete(k) }
                isAuthenticated = false
                return nil
            }
            let tok = try JSONDecoder().decode(TokenResponse.self, from: data)
            keychainSave("access_token", tok.accessToken)
            if let r = tok.refreshToken { keychainSave("refresh_token", r) }
            DebugLog.log("[Auth] Token refreshed successfully")
            return tok.accessToken
        } catch {
            DebugLog.log("[Auth] Refresh error: \(error.localizedDescription)")
            return nil
        }
    }

    func logout() {
        for k in ["access_token", "refresh_token"] { keychainDelete(k) }
        isAuthenticated = false
    }

    // MARK: - Keychain

    private func keychainSave(_ key: String, _ val: String) {
        let q: CFDictionary = [kSecClass: kSecClassGenericPassword,
                                kSecAttrService: "ClaudeFiles",
                                kSecAttrAccount: key] as CFDictionary
        SecItemDelete(q)
        SecItemAdd([kSecClass: kSecClassGenericPassword,
                    kSecAttrService: "ClaudeFiles",
                    kSecAttrAccount: key,
                    kSecValueData: Data(val.utf8)] as CFDictionary, nil)
    }
    private func keychainLoad(_ key: String) -> String? {
        var r: AnyObject?
        SecItemCopyMatching([kSecClass: kSecClassGenericPassword,
                             kSecAttrService: "ClaudeFiles",
                             kSecAttrAccount: key,
                             kSecReturnData: true] as CFDictionary, &r)
        guard let d = r as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    private func keychainDelete(_ key: String) {
        SecItemDelete([kSecClass: kSecClassGenericPassword,
                       kSecAttrService: "ClaudeFiles",
                       kSecAttrAccount: key] as CFDictionary)
    }

    // MARK: - PKCE

    private func pkceChallenge(_ v: String) -> String {
        Data(SHA256.hash(data: Data(v.utf8))).base64URLEncoded()
    }
    private func randomBase64(_ n: Int) -> String {
        var b = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return Data(b).base64URLEncoded()
    }
}

private final class AnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    let anchor: ASPresentationAnchor
    init(anchor: ASPresentationAnchor) { self.anchor = anchor }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchor }
}

private struct TokenResponse: Decodable {
    let accessToken:  String
    let refreshToken: String?
    enum CodingKeys: String, CodingKey {
        case accessToken  = "access_token"
        case refreshToken = "refresh_token"
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
