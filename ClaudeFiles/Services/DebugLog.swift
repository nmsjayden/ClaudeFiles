import Foundation

/// Appends debug lines to a file in Documents/debug.log so we can inspect what's happening.
enum DebugLog {
    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        return f
    }()

    static var logURL: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("debug.log")
    }

    static func log(_ message: String) {
        let timestamp = formatter.string(from: Date())
        let line = "[\(timestamp)] \(message)\n"
        guard let data = line.data(using: .utf8) else { return }

        if FileManager.default.fileExists(atPath: logURL.path) {
            if let handle = try? FileHandle(forWritingTo: logURL) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
            }
        } else {
            try? data.write(to: logURL)
        }
    }

    static func clear() {
        try? FileManager.default.removeItem(at: logURL)
    }

    static func readAll() -> String {
        (try? String(contentsOf: logURL)) ?? "(empty)"
    }
}
