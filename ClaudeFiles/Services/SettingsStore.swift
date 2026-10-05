import Foundation
import SwiftUI

@MainActor
final class SettingsStore: ObservableObject {
    static let shared = SettingsStore()

    @AppStorage("selectedModel") var selectedModel: String = ModelOption.sonnet45.id

    private init() {}
}

struct ModelOption: Identifiable, Hashable {
    let id:          String   // API model string
    let displayName: String
    let subtitle:    String

    static let sonnet45  = ModelOption(id: "claude-sonnet-4-5-20250929",
                                       displayName: "Claude Sonnet 4.5",
                                       subtitle: "Default · fast and capable")
    static let opus41    = ModelOption(id: "claude-opus-4-1-20250805",
                                       displayName: "Claude Opus 4.1",
                                       subtitle: "Most capable · slower")
    static let haiku45   = ModelOption(id: "claude-haiku-4-5",
                                       displayName: "Claude Haiku 4.5",
                                       subtitle: "Fastest · lightweight")

    static let all: [ModelOption] = [sonnet45, opus41, haiku45]
}
