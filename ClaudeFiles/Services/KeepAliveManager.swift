import Foundation
import AVFoundation

/// Prevents iOS from suspending the app by playing a silent audio loop.
/// This keeps API streaming and tool execution alive in the background
/// indefinitely, rather than the ~30s from beginBackgroundTask.
/// Technique from: https://github.com/rooootdev/lara
final class KeepAliveManager {
    static let shared = KeepAliveManager()

    private var player: AVAudioPlayer?
    private(set) var isActive = false

    private init() {}

    /// Start the silent audio keepalive. Call when the app enters background
    /// or when a long-running task begins.
    func activate() {
        guard !isActive else { return }

        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
        } catch {
            DebugLog.log("[KeepAlive] Audio session failed: \(error)")
            return
        }

        let wavURL = silentWAVURL()
        if !FileManager.default.fileExists(atPath: wavURL.path) {
            generateSilentWAV(at: wavURL)
        }

        do {
            player = try AVAudioPlayer(contentsOf: wavURL)
            player?.numberOfLoops = -1  // loop forever
            player?.volume = 0.0
            player?.prepareToPlay()
            player?.play()
            isActive = true
            DebugLog.log("[KeepAlive] Activated — app will stay alive in background")
        } catch {
            DebugLog.log("[KeepAlive] Audio player failed: \(error)")
        }
    }

    /// Stop the keepalive. Call when the app returns to foreground or is done.
    func deactivate() {
        guard isActive else { return }
        player?.stop()
        player = nil
        isActive = false
        DebugLog.log("[KeepAlive] Deactivated")
    }

    // MARK: - Silent WAV generation

    private func silentWAVURL() -> URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("_keepalive_silent.wav")
    }

    /// Generate a 1-second silent WAV file (44100 Hz, 16-bit mono).
    private func generateSilentWAV(at url: URL) {
        let sampleRate = 44100
        let numSamples = sampleRate  // 1 second
        let dataSize = numSamples * 2  // 16-bit = 2 bytes per sample
        let chunkSize = 36 + dataSize

        var wav = Data()

        func append<T>(_ value: T) {
            var v = value
            wav.append(Data(bytes: &v, count: MemoryLayout<T>.size))
        }

        // RIFF header
        wav.append("RIFF".data(using: .ascii)!)
        append(UInt32(chunkSize))
        wav.append("WAVE".data(using: .ascii)!)

        // fmt chunk
        wav.append("fmt ".data(using: .ascii)!)
        append(UInt32(16))              // chunk size
        append(UInt16(1))               // PCM format
        append(UInt16(1))               // mono
        append(UInt32(sampleRate))      // sample rate
        append(UInt32(sampleRate * 2))  // byte rate
        append(UInt16(2))               // block align
        append(UInt16(16))              // bits per sample

        // data chunk (all zeros = silence)
        wav.append("data".data(using: .ascii)!)
        append(UInt32(dataSize))
        wav.append(Data(count: dataSize))

        try? wav.write(to: url)
    }
}
