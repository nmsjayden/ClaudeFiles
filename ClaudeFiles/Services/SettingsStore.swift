import Foundation
import SwiftUI

@MainActor
final class SettingsStore: ObservableObject {
    static let shared = SettingsStore()

    @AppStorage("selectedModel") var selectedModel: String = ModelOption.sonnet55.id
    @AppStorage("autoApproveWrites") var autoApproveWrites: Bool = false
    @AppStorage("appTheme") var appTheme: String = "system"  // "system", "dark", "light"
    @AppStorage("appVersion") var appVersion: String = "1.2.0"

    private init() {}

    func select(_ opt: ModelOption) { selectedModel = opt.id }
    var current: ModelOption { ModelOption.all.first(where: { $0.id == selectedModel }) ?? .sonnet55 }
}

struct ModelOption: Identifiable, Hashable {
    let id:           String
    let displayName:  String
    let shortName:    String   // shown in toolbar
    let subtitle:     String
    let family:       Family
    let isRecommended: Bool
    let isNewest:      Bool

    enum Family: String, CaseIterable {
        case fable  = "Fable"
        case opus   = "Opus"
        case sonnet = "Sonnet"
        case haiku  = "Haiku"

        var systemImage: String {
            switch self {
            case .fable:  return "book.closed.fill"
            case .opus:   return "crown.fill"
            case .sonnet: return "sparkles"
            case .haiku:  return "bolt.fill"
            }
        }
        var tint: Color {
            switch self {
            case .fable:  return .indigo
            case .opus:   return .orange
            case .sonnet: return .purple
            case .haiku:  return .cyan
            }
        }
        var tagline: String {
            switch self {
            case .fable:  return "Demanding reasoning & long-horizon agents"
            case .opus:   return "Deep agentic coding & knowledge work"
            case .sonnet: return "Best balance of speed and intelligence"
            case .haiku:  return "Fastest · near-frontier intelligence"
            }
        }
    }

    // Current flagship lineup
    static let fable51   = ModelOption(id: "claude-fable-5-1",  displayName: "Claude Fable 5.1",  shortName: "Fable 5.1",  subtitle: "Flagship reasoning model",     family: .fable,  isRecommended: false, isNewest: true)
    static let opus55    = ModelOption(id: "claude-opus-5-5",   displayName: "Claude Opus 5.5",   shortName: "Opus 5.5",   subtitle: "Long-running coding & analysis", family: .opus,   isRecommended: false, isNewest: true)
    static let sonnet55  = ModelOption(id: "claude-sonnet-5-5", displayName: "Claude Sonnet 5.5", shortName: "Sonnet 5.5", subtitle: "Default · smart and fast",       family: .sonnet, isRecommended: true,  isNewest: true)
    static let haiku45   = ModelOption(id: "claude-haiku-4-5-20251001", displayName: "Claude Haiku 4.5", shortName: "Haiku 4.5", subtitle: "Fastest model",            family: .haiku,  isRecommended: false, isNewest: true)

    // Previous generation
    static let opus47    = ModelOption(id: "claude-opus-4-7",   displayName: "Claude Opus 4.7",   shortName: "Opus 4.7",   subtitle: "Previous flagship Opus", family: .opus,   isRecommended: false, isNewest: false)
    static let opus46    = ModelOption(id: "claude-opus-4-6",   displayName: "Claude Opus 4.6",   shortName: "Opus 4.6",   subtitle: "Earlier Opus 4.x",       family: .opus,   isRecommended: false, isNewest: false)
    static let sonnet46  = ModelOption(id: "claude-sonnet-4-6", displayName: "Claude Sonnet 4.6", shortName: "Sonnet 4.6", subtitle: "Earlier Sonnet 4.x",     family: .sonnet, isRecommended: false, isNewest: false)
    static let opus41    = ModelOption(id: "claude-opus-4-1-20250805",   displayName: "Claude Opus 4.1",   shortName: "Opus 4.1",   subtitle: "August 2025",     family: .opus,   isRecommended: false, isNewest: false)
    static let sonnet45  = ModelOption(id: "claude-sonnet-4-5-20250929", displayName: "Claude Sonnet 4.5", shortName: "Sonnet 4.5", subtitle: "September 2025", family: .sonnet, isRecommended: false, isNewest: false)

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
