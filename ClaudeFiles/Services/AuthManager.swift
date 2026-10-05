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

    private let clientId     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    private let authorizeURL = "https://claude.ai/oauth/authorize"
    private let tokenURL     = "https://console.anthropic.com/v1/oauth/token"
    private let scopes       = "org:create_api_key user:profile user:inference"
    private let redirectURI  = "claudefiles://oauth/callback"

    private var pendingVerifier: String?
    private var pendingState:    String?
    private var authSession:     ASWebAuthenticationSession?
    // Kept alive for the duration of the session (presentationContextProvider is weak)
    private var anchorProvider:  AnchorProvider?

    private override init() {
        super.init()
        isAuthenticated = (keychainLoad("access_token") != nil)
    }

    // MARK: - Login

    func startLogin(anchor: ASPresentationAnchor) {
        isLoading    = true
        errorMessage = nil

        let verifier  = randomBase64(32)
        let challenge = pkceChallenge(verifier)
        let state     = randomBase64(16)
        pendingVerifier = verifier
        pendingState    = state

        var c = URLComponents(string: authorizeURL)!
        c.queryItems = [
            .init(name: "client_id",            value: clientId),
            .init(name: "response_type",         value: "code"),
            .init(name: "redirect_uri",          value: redirectURI),
            .init(name: "scope",                 value: scopes),
            .init(name: "code_challenge",        value: challenge),
            .init(name: "code_challenge_method", value: "S256"),
            .init(name: "state",                 value: state),
        ]
        guard let url = c.url else { isLoading = false; return }

        // Store provider as a property so it isn't deallocated while session runs
        let provider = AnchorProvider(anchor: anchor)
        anchorProvider = provider

        let session = ASWebAuthenticationSession(
            url: url,
            callbackURLScheme: "claudefiles"
        ) { [weak self] cb, err in
            Task { @MainActor [weak self] in
                self?.handleCallback(url: cb, error: err)
            }
        }
        session.presentationContextProvider = provider
        session.prefersEphemeralWebBrowserSession = false
        session.start()
        authSession = session
    }

    // MARK: - Callback

    func handleCallback(url: URL?, error: Error? = nil) {
        anchorProvider = nil   // safe to release now
        defer { isLoading = false }

        if let e = error as? ASWebAuthenticationSessionError, e.code == .canceledLogin { return }
        if let e = error { errorMessage = e.localizedDescription; return }

        guard
            let url      = url,
            let comps    = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let code     = comps.queryItems?.first(where: { $0.name == "code" })?.value,
            let retState = comps.queryItems?.first(where: { $0.name == "state" })?.value,
            retState     == pendingState,
            let verifier = pendingVerifier
        else { errorMessage = "OAuth callback invalid"; return }

        Task { await exchange(code: code, verifier: verifier) }
    }

    // MARK: - Token exchange

    private func exchange(code: String, verifier: String) async {
        var req = URLRequest(url: URL(string: tokenURL)!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONEncoder().encode([
            "grant_type": "authorization_code", "client_id": clientId,
            "code": code, "redirect_uri": redirectURI, "code_verifier": verifier,
        ])
        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let tok = try JSONDecoder().decode(TokenResponse.self, from: data)
            keychainSave("access_token",  tok.accessToken)
            if let r = tok.refreshToken { keychainSave("refresh_token", r) }
            isAuthenticated = true
        } catch {
            errorMessage = "Sign-in failed: \(error.localizedDescription)"
        }
        isLoading = false
    }

    // MARK: - Token access

    func accessToken() async -> String? {
        keychainLoad("access_token")
    }

    // MARK: - Logout

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
        var add = [kSecClass: kSecClassGenericPassword,
                   kSecAttrService: "ClaudeFiles",
                   kSecAttrAccount: key,
                   kSecValueData: Data(val.utf8)] as CFDictionary
        SecItemAdd(add, nil)
    }
    private func keychainLoad(_ key: String) -> String? {
        let q: CFDictionary = [kSecClass: kSecClassGenericPassword,
                                kSecAttrService: "ClaudeFiles",
                                kSecAttrAccount: key,
                                kSecReturnData: true] as CFDictionary
        var r: AnyObject?
        SecItemCopyMatching(q, &r)
        guard let d = r as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    private func keychainDelete(_ key: String) {
        SecItemDelete([kSecClass: kSecClassGenericPassword,
                       kSecAttrService: "ClaudeFiles",
                       kSecAttrAccount: key] as CFDictionary)
    }

    // MARK: - PKCE

    private func pkceChallenge(_ verifier: String) -> String {
        Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncoded()
    }
    private func randomBase64(_ n: Int) -> String {
        var b = [UInt8](repeating: 0, count: n)
        SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return Data(b).base64URLEncoded()
    }
}

// MARK: - Anchor provider (stored as property to stay alive)

private final class AnchorProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    let anchor: ASPresentationAnchor
    init(anchor: ASPresentationAnchor) { self.anchor = anchor }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { anchor }
}

// MARK: - Helpers

private struct TokenResponse: Decodable {
    let accessToken:  String
    let refreshToken: String?
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"; case refreshToken = "refresh_token"
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
