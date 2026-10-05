import Foundation
import SwiftUI

@MainActor
final class SettingsStore: ObservableObject {
    static let shared = SettingsStore()

    @AppStorage("selectedModel") var selectedModel: String = ModelOption.sonnet55.id

    private init() {}
}

struct ModelOption: Identifiable, Hashable {
    let id:          String
    let displayName: String
    let subtitle:    String
    let family:      Family

    enum Family: String, CaseIterable { case fable = "Fable", opus = "Opus", sonnet = "Sonnet", haiku = "Haiku" }

    // Current flagship lineup
    static let fable51   = ModelOption(id: "claude-fable-5-1",
                                       displayName: "Claude Fable 5.1",
                                       subtitle: "Demanding reasoning · long-horizon agents",
                                       family: .fable)
    static let opus55    = ModelOption(id: "claude-opus-5-5",
                                       displayName: "Claude Opus 5.5",
                                       subtitle: "Long-running agentic coding & knowledge work",
                                       family: .opus)
    static let sonnet55  = ModelOption(id: "claude-sonnet-5-5",
                                       displayName: "Claude Sonnet 5.5",
                                       subtitle: "Best balance of speed and intelligence",
                                       family: .sonnet)
    static let haiku45   = ModelOption(id: "claude-haiku-4-5-20251001",
                                       displayName: "Claude Haiku 4.5",
                                       subtitle: "Fastest · near-frontier intelligence",
                                       family: .haiku)

    // Previous generation (4.x) — kept for people who want them
    static let opus47    = ModelOption(id: "claude-opus-4-7",
                                       displayName: "Claude Opus 4.7",
                                       subtitle: "Previous flagship",
                                       family: .opus)
    static let opus46    = ModelOption(id: "claude-opus-4-6",
                                       displayName: "Claude Opus 4.6",
                                       subtitle: "Earlier Opus 4.x",
                                       family: .opus)
    static let sonnet46  = ModelOption(id: "claude-sonnet-4-6",
                                       displayName: "Claude Sonnet 4.6",
                                       subtitle: "Earlier Sonnet 4.x",
                                       family: .sonnet)
    static let opus41    = ModelOption(id: "claude-opus-4-1-20250805",
                                       displayName: "Claude Opus 4.1",
                                       subtitle: "August 2025",
                                       family: .opus)
    static let sonnet45  = ModelOption(id: "claude-sonnet-4-5-20250929",
                                       displayName: "Claude Sonnet 4.5",
                                       subtitle: "September 2025",
                                       family: .sonnet)

    static let all: [ModelOption] = [
        fable51, opus55, sonnet55, haiku45,
        opus47, opus46, sonnet46, opus41, sonnet45
    ]

    static func grouped() -> [(Family, [ModelOption])] {
        Family.allCases.compactMap { family in
            let items = all.filter { $0.family == family }
            return items.isEmpty ? nil : (family, items)
        }
    }
}
