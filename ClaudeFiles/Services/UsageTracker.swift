import Foundation

/// Tracks Anthropic API rate limits and token usage across the session.
/// Updated from HTTP response headers and SSE usage events.
@MainActor
final class UsageTracker: ObservableObject {
    static let shared = UsageTracker()

    // ── Rate limits (from HTTP response headers) ──────────────────────
    @Published var requestsLimit:     Int = 0
    @Published var requestsRemaining: Int = 0
    @Published var requestsReset:     Date?
    @Published var tokensLimit:       Int = 0
    @Published var tokensRemaining:   Int = 0
    @Published var tokensReset:       Date?

    // ── Per-message usage (from SSE events) ───────────────────────────
    @Published var inputTokens:         Int = 0
    @Published var outputTokens:        Int = 0
    @Published var cacheCreationTokens: Int = 0
    @Published var cacheReadTokens:     Int = 0

    // ── Session totals ────────────────────────────────────────────────
    @Published var sessionInputTokens:  Int = 0
    @Published var sessionOutputTokens: Int = 0
    @Published var sessionRequests:     Int = 0

    @Published var lastUpdated: Date?

    // ── Computed status ───────────────────────────────────────────────

    enum Status: String {
        case good     // > 20% remaining
        case warning  // 5-20% remaining
        case critical // ≤ 5% remaining
        case unknown  // no data yet
    }

    var status: Status {
        guard requestsLimit > 0 || tokensLimit > 0 else { return .unknown }
        let reqRatio   = requestsLimit > 0 ? Double(requestsRemaining) / Double(requestsLimit) : 1.0
        let tokenRatio = tokensLimit   > 0 ? Double(tokensRemaining)   / Double(tokensLimit)   : 1.0
        let minRatio   = min(reqRatio, tokenRatio)
        if minRatio <= 0.05 { return .critical }
        if minRatio <= 0.20 { return .warning }
        return .good
    }

    /// Formatted string for the rate limit that's closest to exhaustion.
    var limitSummary: String {
        guard requestsLimit > 0 || tokensLimit > 0 else { return "No data" }
        // Show whichever is lower
        let reqPct   = requestsLimit > 0 ? Double(requestsRemaining) / Double(requestsLimit) : 1.0
        let tokenPct = tokensLimit   > 0 ? Double(tokensRemaining)   / Double(tokensLimit)   : 1.0
        if reqPct < tokenPct {
            return "\(requestsRemaining)/\(requestsLimit) requests"
        } else {
            return "\(formatTokens(tokensRemaining))/\(formatTokens(tokensLimit)) tokens"
        }
    }

    /// Formatted session total.
    var sessionSummary: String {
        let total = sessionInputTokens + sessionOutputTokens
        return "\(formatTokens(total)) tokens (\(sessionRequests) req)"
    }

    /// Reset time for the tightest limit.
    var nextReset: Date? {
        let reqPct   = requestsLimit > 0 ? Double(requestsRemaining) / Double(requestsLimit) : 1.0
        let tokenPct = tokensLimit   > 0 ? Double(tokensRemaining)   / Double(tokensLimit)   : 1.0
        return reqPct < tokenPct ? requestsReset : tokensReset
    }

    /// Formatted reset countdown.
    var resetCountdown: String? {
        guard let reset = nextReset else { return nil }
        let seconds = Int(reset.timeIntervalSinceNow)
        if seconds <= 0 { return "now" }
        if seconds < 60 { return "\(seconds)s" }
        return "\(seconds / 60)m \(seconds % 60)s"
    }

    // ── Update methods ────────────────────────────────────────────────

    func updateFromHeaders(_ http: HTTPURLResponse) {
        if let v = http.value(forHTTPHeaderField: "anthropic-ratelimit-requests-limit")     { requestsLimit     = Int(v) ?? requestsLimit }
        if let v = http.value(forHTTPHeaderField: "anthropic-ratelimit-requests-remaining") { requestsRemaining = Int(v) ?? requestsRemaining }
        if let v = http.value(forHTTPHeaderField: "anthropic-ratelimit-tokens-limit")       { tokensLimit       = Int(v) ?? tokensLimit }
        if let v = http.value(forHTTPHeaderField: "anthropic-ratelimit-tokens-remaining")   { tokensRemaining   = Int(v) ?? tokensRemaining }

        let isoFmt = ISO8601DateFormatter()
        isoFmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let v = http.value(forHTTPHeaderField: "anthropic-ratelimit-requests-reset") {
            requestsReset = isoFmt.date(from: v) ?? ISO8601DateFormatter().date(from: v)
        }
        if let v = http.value(forHTTPHeaderField: "anthropic-ratelimit-tokens-reset") {
            tokensReset = isoFmt.date(from: v) ?? ISO8601DateFormatter().date(from: v)
        }

        lastUpdated = Date()
    }

    func updateUsage(input: Int, output: Int, cacheCreation: Int = 0, cacheRead: Int = 0) {
        inputTokens         = input
        outputTokens         = output
        cacheCreationTokens = cacheCreation
        cacheReadTokens     = cacheRead
    }

    func updateOutputTokens(_ count: Int) {
        outputTokens = count
    }

    func finishRequest() {
        sessionInputTokens  += inputTokens
        sessionOutputTokens += outputTokens
        sessionRequests     += 1
        inputTokens          = 0
        outputTokens         = 0
        cacheCreationTokens  = 0
        cacheReadTokens      = 0
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private func formatTokens(_ n: Int) -> String {
        if n >= 1_000_000 { return String(format: "%.1fM", Double(n) / 1_000_000) }
        if n >= 1_000     { return String(format: "%.1fK", Double(n) / 1_000) }
        return "\(n)"
    }
}
