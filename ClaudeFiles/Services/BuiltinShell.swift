import Foundation
import CommonCrypto

/// Built-in shell — executes common commands directly in Swift.
/// No process spawning, no posix_spawn, no fork.
/// Works because sandbox escape gives us full filesystem access.
struct BuiltinShell {

    // MARK: - Public API

    /// Try to execute a shell command string.
    /// Returns (output, exitCode) if handled, nil if the command isn't recognized.
    static func exec(_ command: String) -> (output: String, exitCode: Int32)? {
        let cmd = command.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty else { return ("", 0) }

        // Handle compound operators: ; && || |
        // We scan left-to-right outside quotes.
        let segments = splitCompound(cmd)
        if segments.count > 1 {
            return runCompound(segments)
        }

        // Single command (possibly with redirection)
        return runSingle(cmd, stdin: nil)
    }

    // MARK: - Compound commands

    private enum Op { case first, semi, and, or, pipe }
    private struct Segment { let op: Op; let cmd: String }

    private static func splitCompound(_ input: String) -> [Segment] {
        var segs: [Segment] = []
        var cur = ""
        var inSQ = false, inDQ = false, esc = false
        let chars = Array(input)
        var i = 0
        var pendingOp: Op = .first

        while i < chars.count {
            let c = chars[i]
            if esc { cur.append(c); esc = false; i += 1; continue }
            if c == "\\" && !inSQ { esc = true; i += 1; continue }
            if c == "'" && !inDQ { inSQ.toggle(); i += 1; continue }
            if c == "\"" && !inSQ { inDQ.toggle(); i += 1; continue }

            if !inSQ && !inDQ {
                if c == ";" {
                    segs.append(Segment(op: pendingOp, cmd: cur))
                    cur = ""; pendingOp = .semi; i += 1; continue
                }
                if c == "&" && i+1 < chars.count && chars[i+1] == "&" {
                    segs.append(Segment(op: pendingOp, cmd: cur))
                    cur = ""; pendingOp = .and; i += 2; continue
                }
                if c == "|" && (i+1 >= chars.count || chars[i+1] != "|") {
                    segs.append(Segment(op: pendingOp, cmd: cur))
                    cur = ""; pendingOp = .pipe; i += 1; continue
                }
                if c == "|" && i+1 < chars.count && chars[i+1] == "|" {
                    segs.append(Segment(op: pendingOp, cmd: cur))
                    cur = ""; pendingOp = .or; i += 2; continue
                }
            }
            cur.append(c)
            i += 1
        }
        if !cur.trimmingCharacters(in: .whitespaces).isEmpty {
            segs.append(Segment(op: pendingOp, cmd: cur))
        }
        return segs
    }

    private static func runCompound(_ segs: [Segment]) -> (String, Int32)? {
        var output = ""
        var code: Int32 = 0
        var pipeInput: String? = nil

        for seg in segs {
            let trimCmd = seg.cmd.trimmingCharacters(in: .whitespaces)
            guard !trimCmd.isEmpty else { continue }

            switch seg.op {
            case .first, .semi:
                pipeInput = nil
            case .and:
                guard code == 0 else { pipeInput = nil; continue }
                pipeInput = nil
            case .or:
                guard code != 0 else { pipeInput = nil; continue }
                pipeInput = nil
            case .pipe:
                pipeInput = output  // feed previous output
                output = ""
            }

            guard let result = runSingle(trimCmd, stdin: pipeInput) else {
                return nil  // unrecognized command in chain
            }
            if seg.op == .pipe {
                output = result.output
            } else {
                if !output.isEmpty && !result.output.isEmpty { output += "\n" }
                output += result.output
            }
            code = result.exitCode
        }
        return (output, code)
    }

    // MARK: - Single command execution

    private static func runSingle(_ cmd: String, stdin: String?) -> (String, Int32)? {
        var command = cmd

        // Handle output redirection: > file or >> file
        var redirectPath: String? = nil
        var redirectAppend = false

        // Find unquoted > or >>
        if let (newCmd, path, append) = extractRedirection(command) {
            command = newCmd
            redirectPath = path
            redirectAppend = append
        }

        // Tokenize
        let tokens = shellTokenize(command)
        guard let name = tokens.first else { return ("", 0) }
        let args = Array(tokens.dropFirst())

        // Dispatch
        guard var result = dispatch(name: name, args: args, stdin: stdin) else {
            return nil  // not a built-in
        }

        // Apply redirection
        if let path = redirectPath {
            let expandedPath = expandTilde(path)
            do {
                let data = (result.output + "\n").data(using: .utf8) ?? Data()
                if redirectAppend {
                    if FileManager.default.fileExists(atPath: expandedPath) {
                        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: expandedPath))
                        handle.seekToEndOfFile()
                        handle.write(data)
                        handle.closeFile()
                    } else {
                        try data.write(to: URL(fileURLWithPath: expandedPath))
                    }
                } else {
                    try data.write(to: URL(fileURLWithPath: expandedPath))
                }
                result = ("", 0)
            } catch {
                result = ("redirect: \(error.localizedDescription)", 1)
            }
        }

        return result
    }

    // MARK: - Command dispatch

    private static func dispatch(name: String, args: [String], stdin: String?) -> (output: String, exitCode: Int32)? {
        switch name {
        case "echo":     return cmdEcho(args)
        case "printf":   return cmdPrintf(args)
        case "cat":      return cmdCat(args, stdin: stdin)
        case "head":     return cmdHead(args, stdin: stdin)
        case "tail":     return cmdTail(args, stdin: stdin)
        case "wc":       return cmdWc(args, stdin: stdin)
        case "sort":     return cmdSort(args, stdin: stdin)
        case "uniq":     return cmdUniq(args, stdin: stdin)
        case "tr":       return cmdTr(args, stdin: stdin)
        case "grep":     return cmdGrep(args, stdin: stdin)
        case "sed":      return cmdSed(args, stdin: stdin)
        case "cut":      return cmdCut(args, stdin: stdin)
        case "tee":      return cmdTee(args, stdin: stdin)
        case "ls":       return cmdLs(args)
        case "find":     return cmdFind(args)
        case "stat":     return cmdStat(args)
        case "file":     return cmdFile(args)
        case "du":       return cmdDu(args)
        case "df":       return cmdDf(args)
        case "mkdir":    return cmdMkdir(args)
        case "rmdir":    return cmdRmdir(args)
        case "rm":       return cmdRm(args)
        case "cp":       return cmdCp(args)
        case "mv":       return cmdMv(args)
        case "ln":       return cmdLn(args)
        case "touch":    return cmdTouch(args)
        case "chmod":    return cmdChmod(args)
        case "chown":    return cmdChown(args)
        case "id":       return cmdId()
        case "whoami":   return cmdWhoami()
        case "uname":    return cmdUname(args)
        case "hostname": return cmdHostname()
        case "uptime":   return cmdUptime()
        case "date":     return cmdDate(args)
        case "pwd":      return cmdPwd()
        case "env",
             "printenv": return cmdEnv(args)
        case "which":    return cmdWhich(args)
        case "realpath": return cmdRealpath(args)
        case "dirname":  return cmdDirname(args)
        case "basename": return cmdBasename(args)
        case "readlink": return cmdReadlink(args)
        case "ps":       return cmdPs(args)
        case "kill":     return cmdKill(args)
        case "sleep":    return cmdSleep(args)
        case "true":     return ("", 0)
        case "false":    return ("", 1)
        case "test", "[": return cmdTest(args)
        case "expr":     return cmdExpr(args)
        case "seq":      return cmdSeq(args)
        case "yes":      return cmdYes(args)
        case "rev":      return cmdRev(args, stdin: stdin)
        case "md5":      return cmdMd5(args)
        case "shasum":   return cmdShasum(args)
        case "xxd":      return cmdXxd(args)
        case "hexdump":  return cmdXxd(args)
        case "base64":   return cmdBase64(args, stdin: stdin)
        case "strings":  return cmdStrings(args)
        case "xargs":    return cmdXargs(args, stdin: stdin)
        default:         return nil
        }
    }

    // MARK: - Shell tokenizer

    static func shellTokenize(_ input: String) -> [String] {
        var tokens: [String] = []
        var cur = ""
        var inSQ = false, inDQ = false, esc = false
        for c in input {
            if esc { cur.append(c); esc = false; continue }
            if c == "\\" && !inSQ { esc = true; continue }
            if c == "'" && !inDQ { inSQ.toggle(); continue }
            if c == "\"" && !inSQ { inDQ.toggle(); continue }
            if c == " " && !inSQ && !inDQ {
                if !cur.isEmpty { tokens.append(cur); cur = "" }
                continue
            }
            cur.append(c)
        }
        if !cur.isEmpty { tokens.append(cur) }
        return tokens.map { expandTilde($0) }
    }

    // MARK: - Helpers

    private static func expandTilde(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return NSHomeDirectory() + String(path.dropFirst(1))
        }
        if path == "~" { return NSHomeDirectory() }
        return path
    }

    private static func extractRedirection(_ cmd: String) -> (cmd: String, path: String, append: Bool)? {
        // Find last unquoted >> or >
        var inSQ = false, inDQ = false, esc = false
        let chars = Array(cmd)
        var pos = -1
        var isAppend = false

        for i in 0..<chars.count {
            let c = chars[i]
            if esc { esc = false; continue }
            if c == "\\" { esc = true; continue }
            if c == "'" && !inDQ { inSQ.toggle(); continue }
            if c == "\"" && !inSQ { inDQ.toggle(); continue }
            if !inSQ && !inDQ && c == ">" {
                pos = i
                isAppend = (i + 1 < chars.count && chars[i + 1] == ">")
            }
        }
        guard pos >= 0 else { return nil }

        let cmdPart = String(chars[0..<pos]).trimmingCharacters(in: .whitespaces)
        let skip = isAppend ? 2 : 1
        let pathPart = String(chars[(pos + skip)...]).trimmingCharacters(in: .whitespaces)
        guard !pathPart.isEmpty else { return nil }

        let path = shellTokenize(pathPart).first ?? pathPart
        return (cmdPart, path, isAppend)
    }

    private static func readFileLines(_ path: String) -> [String]? {
        guard let data = FileManager.default.contents(atPath: path),
              let str = String(data: data, encoding: .utf8) else { return nil }
        return str.components(separatedBy: "\n")
    }

    private static func formatSize(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes)" }
        let kb = Double(bytes) / 1024
        if kb < 1024 { return String(format: "%.1fK", kb) }
        let mb = kb / 1024
        if mb < 1024 { return String(format: "%.1fM", mb) }
        let gb = mb / 1024
        return String(format: "%.1fG", gb)
    }

    private static func permString(_ mode: mode_t) -> String {
        var s = ""
        let types: [(mode_t, String)] = [
            (S_IFDIR, "d"), (S_IFLNK, "l"), (S_IFCHR, "c"), (S_IFBLK, "b")
        ]
        let ft = mode & S_IFMT
        s += types.first(where: { ft == $0.0 })?.1 ?? "-"
        for shift: mode_t in [6, 3, 0] {
            let bits = (mode >> shift) & 7
            s += (bits & 4 != 0) ? "r" : "-"
            s += (bits & 2 != 0) ? "w" : "-"
            s += (bits & 1 != 0) ? "x" : "-"
        }
        return s
    }

    // MARK: ── Text commands ──

    private static func cmdEcho(_ args: [String]) -> (String, Int32) {
        var noNewline = false
        var items = args
        if items.first == "-n" { noNewline = true; items.removeFirst() }
        _ = noNewline  // newline is implicit in our return
        return (items.joined(separator: " "), 0)
    }

    private static func cmdPrintf(_ args: [String]) -> (String, Int32) {
        guard let fmt = args.first else { return ("", 0) }
        // Very basic printf: just handle %s and %d
        var out = fmt
        var idx = 1
        while out.contains("%s") && idx < args.count {
            out = out.replacingOccurrences(of: "%s", with: args[idx], options: [], range: out.range(of: "%s"))
            idx += 1
        }
        out = out.replacingOccurrences(of: "\\n", with: "\n")
        out = out.replacingOccurrences(of: "\\t", with: "\t")
        return (out, 0)
    }

    private static func cmdCat(_ args: [String], stdin: String?) -> (String, Int32) {
        if args.isEmpty {
            return (stdin ?? "", 0)
        }
        var output = ""
        var code: Int32 = 0
        for path in args {
            if path == "-" { output += stdin ?? ""; continue }
            let expanded = expandTilde(path)
            guard let data = FileManager.default.contents(atPath: expanded),
                  let str = String(data: data, encoding: .utf8) else {
                output += "cat: \(path): No such file or directory\n"
                code = 1; continue
            }
            output += str
        }
        return (output.hasSuffix("\n") ? String(output.dropLast()) : output, code)
    }

    private static func cmdHead(_ args: [String], stdin: String?) -> (String, Int32) {
        var n = 10
        var files: [String] = []
        var i = 0
        while i < args.count {
            if args[i] == "-n" && i + 1 < args.count {
                n = Int(args[i + 1]) ?? 10; i += 2
            } else if args[i].hasPrefix("-") && Int(args[i].dropFirst()) != nil {
                n = Int(args[i].dropFirst()) ?? 10; i += 1
            } else {
                files.append(args[i]); i += 1
            }
        }
        let text = files.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "head: \(files[0]): No such file")
        let lines = text.components(separatedBy: "\n")
        return (lines.prefix(n).joined(separator: "\n"), 0)
    }

    private static func cmdTail(_ args: [String], stdin: String?) -> (String, Int32) {
        var n = 10
        var files: [String] = []
        var i = 0
        while i < args.count {
            if args[i] == "-n" && i + 1 < args.count {
                n = Int(args[i + 1]) ?? 10; i += 2
            } else if args[i].hasPrefix("-") && Int(args[i].dropFirst()) != nil {
                n = Int(args[i].dropFirst()) ?? 10; i += 1
            } else {
                files.append(args[i]); i += 1
            }
        }
        let text = files.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "tail: \(files[0]): No such file")
        let lines = text.components(separatedBy: "\n")
        let start = max(0, lines.count - n)
        return (lines.suffix(from: start).joined(separator: "\n"), 0)
    }

    private static func cmdWc(_ args: [String], stdin: String?) -> (String, Int32) {
        var flags = Set<Character>()
        var files: [String] = []
        for a in args {
            if a.hasPrefix("-") { for c in a.dropFirst() { flags.insert(c) } }
            else { files.append(a) }
        }
        let text = files.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "")
        let lines = text.components(separatedBy: "\n").count - (text.hasSuffix("\n") ? 1 : 0)
        let words = text.split(whereSeparator: { $0.isWhitespace }).count
        let bytes = text.utf8.count
        if flags.contains("l") { return ("\(lines)", 0) }
        if flags.contains("w") { return ("\(words)", 0) }
        if flags.contains("c") { return ("\(bytes)", 0) }
        let name = files.first ?? ""
        return ("  \(lines)  \(words)  \(bytes) \(name)".trimmingCharacters(in: .whitespaces), 0)
    }

    private static func cmdSort(_ args: [String], stdin: String?) -> (String, Int32) {
        let reverse = args.contains("-r")
        let numeric = args.contains("-n")
        let files = args.filter { !$0.hasPrefix("-") }
        let text = files.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "")
        var lines = text.components(separatedBy: "\n")
        if lines.last == "" { lines.removeLast() }
        if numeric {
            lines.sort { (Double($0) ?? 0) < (Double($1) ?? 0) }
        } else {
            lines.sort()
        }
        if reverse { lines.reverse() }
        return (lines.joined(separator: "\n"), 0)
    }

    private static func cmdUniq(_ args: [String], stdin: String?) -> (String, Int32) {
        let countFlag = args.contains("-c")
        let files = args.filter { !$0.hasPrefix("-") }
        let text = files.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "")
        var lines = text.components(separatedBy: "\n")
        if lines.last == "" { lines.removeLast() }
        var result: [String] = []
        var prev = ""
        var count = 0
        for line in lines {
            if line == prev { count += 1 }
            else {
                if count > 0 {
                    result.append(countFlag ? "   \(count) \(prev)" : prev)
                }
                prev = line; count = 1
            }
        }
        if count > 0 { result.append(countFlag ? "   \(count) \(prev)" : prev) }
        return (result.joined(separator: "\n"), 0)
    }

    private static func cmdTr(_ args: [String], stdin: String?) -> (String, Int32) {
        guard args.count >= 2 else { return ("tr: missing operand", 1) }
        let deleteMode = args[0] == "-d"
        if deleteMode {
            guard args.count >= 2 else { return ("tr: missing operand", 1) }
            let chars = CharacterSet(charactersIn: args[1])
            let result = (stdin ?? "").unicodeScalars.filter { !chars.contains($0) }
            return (String(String.UnicodeScalarView(result)), 0)
        }
        let set1 = Array(args[0])
        let set2 = Array(args[1])
        var map: [Character: Character] = [:]
        for (i, c) in set1.enumerated() {
            map[c] = i < set2.count ? set2[i] : set2.last ?? c
        }
        let result = String((stdin ?? "").map { map[$0] ?? $0 })
        return (result, 0)
    }

    private static func cmdGrep(_ args: [String], stdin: String?) -> (String, Int32) {
        var ignoreCase = false, invertMatch = false, countOnly = false
        var recursive = false, lineNumbers = false, filesOnly = false
        var pattern: String? = nil
        var paths: [String] = []

        var i = 0
        while i < args.count {
            let a = args[i]
            if a.hasPrefix("-") && a != "-" && pattern == nil {
                for c in a.dropFirst() {
                    switch c {
                    case "i": ignoreCase = true
                    case "v": invertMatch = true
                    case "c": countOnly = true
                    case "r", "R": recursive = true
                    case "n": lineNumbers = true
                    case "l": filesOnly = true
                    default: break
                    }
                }
            } else if pattern == nil {
                pattern = a
            } else {
                paths.append(a)
            }
            i += 1
        }

        guard let pat = pattern else { return ("grep: missing pattern", 2) }

        func matches(_ line: String) -> Bool {
            let s = ignoreCase ? line.lowercased() : line
            let p = ignoreCase ? pat.lowercased() : pat
            return s.contains(p) != invertMatch
        }

        func grepFile(_ path: String) -> [String] {
            guard let data = FileManager.default.contents(atPath: path),
                  let text = String(data: data, encoding: .utf8) else { return [] }
            let lines = text.components(separatedBy: "\n")
            var result: [String] = []
            let prefix = paths.count > 1 || recursive ? "\(path):" : ""
            if filesOnly {
                if lines.contains(where: matches) { result.append(path) }
                return result
            }
            for (idx, line) in lines.enumerated() {
                guard matches(line) else { continue }
                let ln = lineNumbers ? "\(idx + 1):" : ""
                result.append("\(prefix)\(ln)\(line)")
            }
            return result
        }

        func grepDir(_ dir: String) -> [String] {
            var results: [String] = []
            guard let enumerator = FileManager.default.enumerator(atPath: dir) else { return results }
            while let file = enumerator.nextObject() as? String {
                let full = (dir as NSString).appendingPathComponent(file)
                var isDir: ObjCBool = false
                if FileManager.default.fileExists(atPath: full, isDirectory: &isDir) && !isDir.boolValue {
                    results.append(contentsOf: grepFile(full))
                }
            }
            return results
        }

        if paths.isEmpty {
            // grep from stdin
            let lines = (stdin ?? "").components(separatedBy: "\n")
            if countOnly {
                return ("\(lines.filter(matches).count)", 0)
            }
            let matched = lines.filter(matches)
            return (matched.joined(separator: "\n"), matched.isEmpty ? 1 : 0)
        }

        var allResults: [String] = []
        for path in paths {
            let expanded = expandTilde(path)
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: expanded, isDirectory: &isDir) {
                if isDir.boolValue && recursive {
                    allResults.append(contentsOf: grepDir(expanded))
                } else if !isDir.boolValue {
                    allResults.append(contentsOf: grepFile(expanded))
                }
            }
        }
        if countOnly { return ("\(allResults.count)", 0) }
        return (allResults.joined(separator: "\n"), allResults.isEmpty ? 1 : 0)
    }

    private static func cmdSed(_ args: [String], stdin: String?) -> (String, Int32) {
        // Only handle s/old/new/[g] for now
        var files: [String] = []
        var inPlace = false
        var expr: String? = nil

        var i = 0
        while i < args.count {
            if args[i] == "-i" { inPlace = true }
            else if args[i] == "-e" && i + 1 < args.count { i += 1; expr = args[i] }
            else if expr == nil && args[i].hasPrefix("s") { expr = args[i] }
            else { files.append(args[i]) }
            i += 1
        }
        guard let e = expr, e.hasPrefix("s") else { return ("sed: unsupported expression", 1) }
        let sep = e[e.index(after: e.startIndex)]
        let parts = e.dropFirst(2).components(separatedBy: String(sep))
        guard parts.count >= 2 else { return ("sed: bad substitution", 1) }
        let old = parts[0], new = parts[1]
        let global = parts.count > 2 && parts[2].contains("g")

        func process(_ text: String) -> String {
            if global {
                return text.replacingOccurrences(of: old, with: new)
            }
            var result = text
            if let range = result.range(of: old) {
                result.replaceSubrange(range, with: new)
            }
            return result
        }

        let text = files.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "")
        let lines = text.components(separatedBy: "\n")
        let processed = lines.map(process).joined(separator: "\n")

        if inPlace && !files.isEmpty {
            try? processed.write(toFile: expandTilde(files[0]), atomically: true, encoding: .utf8)
            return ("", 0)
        }
        return (processed.hasSuffix("\n") ? String(processed.dropLast()) : processed, 0)
    }

    private static func cmdCut(_ args: [String], stdin: String?) -> (String, Int32) {
        var delimiter = "\t"
        var fields: [Int] = []
        var files: [String] = []
        var i = 0
        while i < args.count {
            if args[i] == "-d" && i + 1 < args.count { delimiter = args[i+1]; i += 2 }
            else if args[i] == "-f" && i + 1 < args.count {
                fields = args[i+1].split(separator: ",").compactMap { Int($0) }; i += 2
            } else { files.append(args[i]); i += 1 }
        }
        let text = files.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "")
        let lines = text.components(separatedBy: "\n")
        let result = lines.map { line -> String in
            let parts = line.components(separatedBy: delimiter)
            return fields.compactMap { f -> String? in
                let idx = f - 1
                return idx >= 0 && idx < parts.count ? parts[idx] : nil
            }.joined(separator: delimiter)
        }
        return (result.joined(separator: "\n"), 0)
    }

    private static func cmdTee(_ args: [String], stdin: String?) -> (String, Int32) {
        let append = args.contains("-a")
        let files = args.filter { !$0.hasPrefix("-") }
        let input = stdin ?? ""
        for f in files {
            let path = expandTilde(f)
            let data = (input + "\n").data(using: .utf8) ?? Data()
            if append && FileManager.default.fileExists(atPath: path) {
                if let handle = FileHandle(forWritingAtPath: path) {
                    handle.seekToEndOfFile(); handle.write(data); handle.closeFile()
                }
            } else {
                try? data.write(to: URL(fileURLWithPath: path))
            }
        }
        return (input, 0)
    }

    // MARK: ── File listing & search ──

    private static func cmdLs(_ args: [String]) -> (String, Int32) {
        var longFormat = false, showAll = false, humanSize = false, onePerLine = false
        var paths: [String] = []
        for a in args {
            if a.hasPrefix("-") {
                for c in a.dropFirst() {
                    switch c {
                    case "l": longFormat = true
                    case "a": showAll = true
                    case "h": humanSize = true
                    case "1": onePerLine = true
                    default: break
                    }
                }
            } else { paths.append(a) }
        }
        if paths.isEmpty { paths = ["."] }

        var output: [String] = []
        for path in paths {
            let expanded = expandTilde(path)
            let fm = FileManager.default
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: expanded, isDirectory: &isDir) else {
                output.append("ls: \(path): No such file or directory")
                continue
            }

            if !isDir.boolValue {
                // Single file
                if longFormat {
                    output.append(lsLongLine(expanded, name: (expanded as NSString).lastPathComponent, humanSize: humanSize))
                } else {
                    output.append((expanded as NSString).lastPathComponent)
                }
                continue
            }

            if paths.count > 1 { output.append("\(path):") }
            do {
                var items = try fm.contentsOfDirectory(atPath: expanded)
                if !showAll { items = items.filter { !$0.hasPrefix(".") } }
                items.sort()

                if longFormat {
                    for item in items {
                        let full = (expanded as NSString).appendingPathComponent(item)
                        output.append(lsLongLine(full, name: item, humanSize: humanSize))
                    }
                } else if onePerLine {
                    output.append(contentsOf: items)
                } else {
                    output.append(items.joined(separator: "  "))
                }
            } catch {
                output.append("ls: \(path): \(error.localizedDescription)")
            }
        }
        return (output.joined(separator: "\n"), 0)
    }

    private static func lsLongLine(_ path: String, name: String, humanSize: Bool) -> String {
        var st = stat()
        lstat(path, &st)
        let perm = permString(mode_t(st.st_mode))
        let size = humanSize ? formatSize(UInt64(st.st_size)) : "\(st.st_size)"
        let date = Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec))
        let df = DateFormatter()
        df.dateFormat = "MMM dd HH:mm"
        let dateStr = df.string(from: date)
        let nlink = st.st_nlink
        let uid = st.st_uid
        let gid = st.st_gid
        return String(format: "%@ %3d %5d %5d %8@ %@ %@",
                      perm, nlink, uid, gid, size, dateStr, name)
    }

    private static func cmdFind(_ args: [String]) -> (String, Int32) {
        var paths: [String] = ["."]
        var namePattern: String? = nil
        var typeFilter: String? = nil
        var maxDepth = Int.max

        var i = 0
        // First, collect paths (non-flag args before any flag)
        var foundFlag = false
        while i < args.count {
            if args[i].hasPrefix("-") { foundFlag = true }
            if !foundFlag { paths = [args[i]] }
            if args[i] == "-name" && i + 1 < args.count { namePattern = args[i+1]; i += 2; continue }
            if args[i] == "-type" && i + 1 < args.count { typeFilter = args[i+1]; i += 2; continue }
            if args[i] == "-maxdepth" && i + 1 < args.count { maxDepth = Int(args[i+1]) ?? Int.max; i += 2; continue }
            i += 1
        }

        var results: [String] = []
        for path in paths {
            let expanded = expandTilde(path)
            guard let enumerator = FileManager.default.enumerator(atPath: expanded) else { continue }
            results.append(expanded)
            while let file = enumerator.nextObject() as? String {
                if enumerator.level > maxDepth { enumerator.skipDescendants(); continue }
                let full = (expanded as NSString).appendingPathComponent(file)
                let name = (file as NSString).lastPathComponent
                // Name filter (simple glob with * support)
                if let pat = namePattern {
                    if !matchGlob(name, pattern: pat) { continue }
                }
                // Type filter
                if let t = typeFilter {
                    var isDir: ObjCBool = false
                    FileManager.default.fileExists(atPath: full, isDirectory: &isDir)
                    if t == "f" && isDir.boolValue { continue }
                    if t == "d" && !isDir.boolValue { continue }
                }
                results.append(full)
            }
        }
        return (results.joined(separator: "\n"), 0)
    }

    private static func matchGlob(_ str: String, pattern: String) -> Bool {
        // Simple glob: * matches any, ? matches one char
        let regex = "^" + NSRegularExpression.escapedPattern(for: pattern)
            .replacingOccurrences(of: "\\*", with: ".*")
            .replacingOccurrences(of: "\\?", with: ".") + "$"
        return str.range(of: regex, options: .regularExpression, range: str.startIndex..<str.endIndex) != nil
    }

    private static func cmdStat(_ args: [String]) -> (String, Int32) {
        let files = args.filter { !$0.hasPrefix("-") }
        guard !files.isEmpty else { return ("stat: missing operand", 1) }
        var output: [String] = []
        for f in files {
            let path = expandTilde(f)
            var st = Darwin.stat()
            guard lstat(path, &st) == 0 else {
                output.append("stat: \(f): No such file or directory"); continue
            }
            let size = st.st_size
            let blocks = st.st_blocks
            let mode = String(format: "%o", st.st_mode)
            let uid = st.st_uid, gid = st.st_gid
            let mtime = Date(timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec))
            output.append("  File: \(f)")
            output.append("  Size: \(size)  Blocks: \(blocks)")
            output.append("  Mode: \(mode)  Uid: \(uid)  Gid: \(gid)")
            output.append("Modify: \(mtime)")
        }
        return (output.joined(separator: "\n"), 0)
    }

    private static func cmdFile(_ args: [String]) -> (String, Int32) {
        let files = args.filter { !$0.hasPrefix("-") }
        var output: [String] = []
        for f in files {
            let path = expandTilde(f)
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else {
                output.append("\(f): cannot stat"); continue
            }
            if isDir.boolValue { output.append("\(f): directory"); continue }
            if let data = FileManager.default.contents(atPath: path), data.count >= 4 {
                let magic = data.prefix(4)
                if magic.starts(with: [0x89, 0x50, 0x4E, 0x47]) { output.append("\(f): PNG image") }
                else if magic.starts(with: [0xFF, 0xD8]) { output.append("\(f): JPEG image") }
                else if magic.starts(with: [0x25, 0x50, 0x44, 0x46]) { output.append("\(f): PDF document") }
                else if magic.starts(with: [0xCF, 0xFA, 0xED, 0xFE]) { output.append("\(f): Mach-O binary") }
                else if magic.starts(with: [0xCA, 0xFE, 0xBA, 0xBE]) { output.append("\(f): Mach-O universal binary") }
                else if magic.starts(with: [0x50, 0x4B, 0x03, 0x04]) { output.append("\(f): ZIP archive") }
                else if String(data: data.prefix(512), encoding: .utf8) != nil { output.append("\(f): ASCII text") }
                else { output.append("\(f): data") }
            } else { output.append("\(f): empty") }
        }
        return (output.joined(separator: "\n"), 0)
    }

    private static func cmdDu(_ args: [String]) -> (String, Int32) {
        var humanReadable = false, summary = false
        var paths: [String] = []
        for a in args {
            if a.hasPrefix("-") { for c in a.dropFirst() { if c == "h" { humanReadable = true }; if c == "s" { summary = true } } }
            else { paths.append(a) }
        }
        if paths.isEmpty { paths = ["."] }
        var output: [String] = []
        for path in paths {
            let expanded = expandTilde(path)
            var total: UInt64 = 0
            if let enumerator = FileManager.default.enumerator(atPath: expanded) {
                while let file = enumerator.nextObject() as? String {
                    let full = (expanded as NSString).appendingPathComponent(file)
                    var st = Darwin.stat()
                    if lstat(full, &st) == 0 { total += UInt64(st.st_size) }
                }
            }
            let sizeStr = humanReadable ? formatSize(total) : "\(total / 512)"
            output.append("\(sizeStr)\t\(path)")
        }
        return (output.joined(separator: "\n"), 0)
    }

    private static func cmdDf(_ args: [String]) -> (String, Int32) {
        let humanReadable = args.contains("-h")
        let path = args.filter({ !$0.hasPrefix("-") }).first ?? "/"
        do {
            let attrs = try FileManager.default.attributesOfFileSystem(forPath: path)
            let total = (attrs[.systemSize] as? UInt64) ?? 0
            let free = (attrs[.systemFreeSize] as? UInt64) ?? 0
            let used = total - free
            if humanReadable {
                return ("Filesystem  Size  Used  Avail  Use%\n/          \(formatSize(total))  \(formatSize(used))  \(formatSize(free))  \(total > 0 ? Int(Double(used) / Double(total) * 100) : 0)%", 0)
            }
            return ("Filesystem  1K-blocks  Used  Available  Use%\n/  \(total/1024)  \(used/1024)  \(free/1024)  \(total > 0 ? Int(Double(used) / Double(total) * 100) : 0)%", 0)
        } catch {
            return ("df: \(error.localizedDescription)", 1)
        }
    }

    // MARK: ── File operations ──

    private static func cmdMkdir(_ args: [String]) -> (String, Int32) {
        let parents = args.contains("-p")
        let dirs = args.filter { !$0.hasPrefix("-") }
        guard !dirs.isEmpty else { return ("mkdir: missing operand", 1) }
        for d in dirs {
            let path = expandTilde(d)
            do {
                try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: parents)
            } catch { return ("mkdir: \(d): \(error.localizedDescription)", 1) }
        }
        return ("", 0)
    }

    private static func cmdRmdir(_ args: [String]) -> (String, Int32) {
        for d in args.filter({ !$0.hasPrefix("-") }) {
            do { try FileManager.default.removeItem(atPath: expandTilde(d)) }
            catch { return ("rmdir: \(d): \(error.localizedDescription)", 1) }
        }
        return ("", 0)
    }

    private static func cmdRm(_ args: [String]) -> (String, Int32) {
        var recursive = false, force = false
        var files: [String] = []
        for a in args {
            if a.hasPrefix("-") { for c in a.dropFirst() { if c == "r" || c == "R" { recursive = true }; if c == "f" { force = true } } }
            else { files.append(a) }
        }
        for f in files {
            let path = expandTilde(f)
            do {
                var isDir: ObjCBool = false
                if FileManager.default.fileExists(atPath: path, isDirectory: &isDir) {
                    if isDir.boolValue && !recursive {
                        if !force { return ("rm: \(f): is a directory", 1) }
                    } else {
                        try FileManager.default.removeItem(atPath: path)
                    }
                } else if !force {
                    return ("rm: \(f): No such file or directory", 1)
                }
            } catch {
                if !force { return ("rm: \(f): \(error.localizedDescription)", 1) }
            }
        }
        return ("", 0)
    }

    private static func cmdCp(_ args: [String]) -> (String, Int32) {
        var recursive = false
        var files: [String] = []
        for a in args {
            if a.hasPrefix("-") { for c in a.dropFirst() { if c == "r" || c == "R" { recursive = true } } }
            else { files.append(a) }
        }
        guard files.count >= 2 else { return ("cp: missing operand", 1) }
        let dest = expandTilde(files.removeLast())
        for src in files {
            let srcPath = expandTilde(src)
            do { try FileManager.default.copyItem(atPath: srcPath, toPath: dest) }
            catch { return ("cp: \(error.localizedDescription)", 1) }
        }
        _ = recursive  // FileManager.copyItem handles directories
        return ("", 0)
    }

    private static func cmdMv(_ args: [String]) -> (String, Int32) {
        let files = args.filter { !$0.hasPrefix("-") }
        guard files.count >= 2 else { return ("mv: missing operand", 1) }
        let dest = expandTilde(files.last!)
        for src in files.dropLast() {
            do { try FileManager.default.moveItem(atPath: expandTilde(src), toPath: dest) }
            catch { return ("mv: \(error.localizedDescription)", 1) }
        }
        return ("", 0)
    }

    private static func cmdLn(_ args: [String]) -> (String, Int32) {
        let symbolic = args.contains("-s")
        let files = args.filter { !$0.hasPrefix("-") }
        guard files.count == 2 else { return ("ln: need source and target", 1) }
        let src = expandTilde(files[0]), dst = expandTilde(files[1])
        do {
            if symbolic { try FileManager.default.createSymbolicLink(atPath: dst, withDestinationPath: src) }
            else { try FileManager.default.linkItem(atPath: src, toPath: dst) }
        } catch { return ("ln: \(error.localizedDescription)", 1) }
        return ("", 0)
    }

    private static func cmdTouch(_ args: [String]) -> (String, Int32) {
        for f in args.filter({ !$0.hasPrefix("-") }) {
            let path = expandTilde(f)
            if !FileManager.default.fileExists(atPath: path) {
                FileManager.default.createFile(atPath: path, contents: nil)
            } else {
                try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: path)
            }
        }
        return ("", 0)
    }

    private static func cmdChmod(_ args: [String]) -> (String, Int32) {
        let files = args.filter { !$0.hasPrefix("-") }
        guard files.count >= 2 else { return ("chmod: missing operand", 1) }
        guard let mode = UInt16(files[0], radix: 8) else { return ("chmod: invalid mode '\(files[0])'", 1) }
        for f in files.dropFirst() {
            let path = expandTilde(f)
            do {
                try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: path)
            } catch { return ("chmod: \(error.localizedDescription)", 1) }
        }
        return ("", 0)
    }

    private static func cmdChown(_ args: [String]) -> (String, Int32) {
        // chown on iOS without root is unlikely to work, but handle gracefully
        return ("chown: Operation not permitted (sandboxed process)", 1)
    }

    // MARK: ── System info ──

    private static func cmdId() -> (String, Int32) {
        let uid = getuid(), euid = geteuid()
        let gid = getgid(), egid = getegid()
        var uidName = "\(uid)"
        var gidName = "\(gid)"
        if let pw = getpwuid(uid) { uidName = String(cString: pw.pointee.pw_name) }
        if let gr = getgrgid(gid) { gidName = String(cString: gr.pointee.gr_name) }
        return ("uid=\(uid)(\(uidName)) gid=\(gid)(\(gidName)) euid=\(euid) egid=\(egid)", 0)
    }

    private static func cmdWhoami() -> (String, Int32) {
        if let pw = getpwuid(getuid()) {
            return (String(cString: pw.pointee.pw_name), 0)
        }
        return ("uid:\(getuid())", 0)
    }

    private static func cmdUname(_ args: [String]) -> (String, Int32) {
        var u = utsname()
        uname(&u)
        let sysname = withUnsafePointer(to: &u.sysname) { ptr in
            String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
        }
        let nodename = withUnsafePointer(to: &u.nodename) { ptr in
            String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
        }
        let release = withUnsafePointer(to: &u.release) { ptr in
            String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
        }
        let version = withUnsafePointer(to: &u.version) { ptr in
            String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
        }
        let machine = withUnsafePointer(to: &u.machine) { ptr in
            String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
        }

        if args.contains("-a") {
            return ("\(sysname) \(nodename) \(release) \(version) \(machine)", 0)
        }
        if args.contains("-s") { return (sysname, 0) }
        if args.contains("-n") { return (nodename, 0) }
        if args.contains("-r") { return (release, 0) }
        if args.contains("-v") { return (version, 0) }
        if args.contains("-m") { return (machine, 0) }
        return (sysname, 0)
    }

    private static func cmdHostname() -> (String, Int32) {
        var name = [CChar](repeating: 0, count: 256)
        gethostname(&name, 256)
        return (String(cString: name), 0)
    }

    private static func cmdUptime() -> (String, Int32) {
        var boottime = timeval()
        var size = MemoryLayout<timeval>.size
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        sysctl(&mib, 2, &boottime, &size, nil, 0)
        let uptime = time(nil) - boottime.tv_sec
        let days = uptime / 86400
        let hours = (uptime % 86400) / 3600
        let mins = (uptime % 3600) / 60
        if days > 0 {
            return ("up \(days) day(s), \(hours):\(String(format: "%02d", mins))", 0)
        }
        return ("up \(hours):\(String(format: "%02d", mins))", 0)
    }

    private static func cmdDate(_ args: [String]) -> (String, Int32) {
        let df = DateFormatter()
        if let fmtIdx = args.firstIndex(of: "+"), fmtIdx + 1 < args.count {
            var fmt = args[fmtIdx + 1]
            // Convert strftime to DateFormatter
            fmt = fmt.replacingOccurrences(of: "%Y", with: "yyyy")
            fmt = fmt.replacingOccurrences(of: "%m", with: "MM")
            fmt = fmt.replacingOccurrences(of: "%d", with: "dd")
            fmt = fmt.replacingOccurrences(of: "%H", with: "HH")
            fmt = fmt.replacingOccurrences(of: "%M", with: "mm")
            fmt = fmt.replacingOccurrences(of: "%S", with: "ss")
            df.dateFormat = fmt
        } else if let fmt = args.first, fmt.hasPrefix("+") {
            var f = String(fmt.dropFirst())
            f = f.replacingOccurrences(of: "%Y", with: "yyyy")
            f = f.replacingOccurrences(of: "%m", with: "MM")
            f = f.replacingOccurrences(of: "%d", with: "dd")
            f = f.replacingOccurrences(of: "%H", with: "HH")
            f = f.replacingOccurrences(of: "%M", with: "mm")
            f = f.replacingOccurrences(of: "%S", with: "ss")
            df.dateFormat = f
        } else {
            df.dateFormat = "EEE MMM dd HH:mm:ss zzz yyyy"
        }
        return (df.string(from: Date()), 0)
    }

    private static func cmdPwd() -> (String, Int32) {
        return (FileManager.default.currentDirectoryPath, 0)
    }

    private static func cmdEnv(_ args: [String]) -> (String, Int32) {
        if args.isEmpty {
            let env = ProcessInfo.processInfo.environment
            return (env.sorted(by: { $0.key < $1.key }).map { "\($0.key)=\($0.value)" }.joined(separator: "\n"), 0)
        }
        // printenv VAR
        let key = args[0]
        if let val = ProcessInfo.processInfo.environment[key] {
            return (val, 0)
        }
        return ("", 1)
    }

    private static func cmdWhich(_ args: [String]) -> (String, Int32) {
        let pathDirs = (ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin")
            .split(separator: ":").map(String.init)
        var output: [String] = []
        for cmd in args {
            var found = false
            for dir in pathDirs {
                let full = (dir as NSString).appendingPathComponent(cmd)
                if FileManager.default.isExecutableFile(atPath: full) {
                    output.append(full); found = true; break
                }
            }
            if !found { output.append("\(cmd) not found") }
        }
        return (output.joined(separator: "\n"), 0)
    }

    private static func cmdRealpath(_ args: [String]) -> (String, Int32) {
        guard let f = args.first else { return ("realpath: missing operand", 1) }
        let path = expandTilde(f)
        let url = URL(fileURLWithPath: path).standardized
        return (url.path, 0)
    }

    private static func cmdDirname(_ args: [String]) -> (String, Int32) {
        guard let f = args.first else { return ("", 1) }
        return ((f as NSString).deletingLastPathComponent, 0)
    }

    private static func cmdBasename(_ args: [String]) -> (String, Int32) {
        guard let f = args.first else { return ("", 1) }
        var name = (f as NSString).lastPathComponent
        if args.count > 1 && name.hasSuffix(args[1]) {
            name = String(name.dropLast(args[1].count))
        }
        return (name, 0)
    }

    private static func cmdReadlink(_ args: [String]) -> (String, Int32) {
        let f = args.contains("-f") ? args.filter({ !$0.hasPrefix("-") }).first : args.first
        guard let path = f else { return ("readlink: missing operand", 1) }
        let expanded = expandTilde(path)
        do {
            let target = try FileManager.default.destinationOfSymbolicLink(atPath: expanded)
            return (target, 0)
        } catch {
            return ("readlink: \(path): \(error.localizedDescription)", 1)
        }
    }

    // MARK: ── Process commands ──

    private static func cmdPs(_ args: [String]) -> (String, Int32) {
        // Use sysctl to list processes
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        sysctl(&mib, 4, nil, &size, nil, 0)
        let count = size / MemoryLayout<kinfo_proc>.size
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        sysctl(&mib, 4, &procs, &size, nil, 0)
        let actualCount = size / MemoryLayout<kinfo_proc>.size

        var output = "  PID  PPID  UID COMM"
        for i in 0..<actualCount {
            let p = procs[i]
            let pid = p.kp_proc.p_pid
            let ppid = p.kp_eproc.e_ppid
            let uid = p.kp_eproc.e_ucred.cr_uid
            let name = withUnsafePointer(to: p.kp_proc.p_comm) { ptr in
                String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
            }
            output += String(format: "\n%5d %5d %4d %@", pid, ppid, uid, name)
        }
        return (output, 0)
    }

    private static func cmdKill(_ args: [String]) -> (String, Int32) {
        var sig: Int32 = SIGTERM
        var pids: [Int32] = []
        for a in args {
            if a.hasPrefix("-") {
                if let s = Int32(a.dropFirst()) { sig = s }
                else if a == "-9" || a == "-KILL" { sig = SIGKILL }
                else if a == "-HUP" { sig = SIGHUP }
            } else if let pid = Int32(a) { pids.append(pid) }
        }
        for pid in pids {
            if kill(pid, sig) != 0 {
                return ("kill: \(pid): \(String(cString: strerror(errno)))", 1)
            }
        }
        return ("", 0)
    }

    private static func cmdSleep(_ args: [String]) -> (String, Int32) {
        guard let secs = args.first.flatMap({ Double($0) }) else { return ("sleep: missing operand", 1) }
        let capped = min(secs, 30)  // cap at 30s to not freeze the app
        Thread.sleep(forTimeInterval: capped)
        return ("", 0)
    }

    // MARK: ── Misc utility ──

    private static func cmdTest(_ args: [String]) -> (String, Int32) {
        var a = args
        if a.last == "]" { a.removeLast() }
        if a.count == 1 { return ("", !a[0].isEmpty ? 0 : 1) }
        if a.count == 2 {
            switch a[0] {
            case "-f": return ("", FileManager.default.fileExists(atPath: expandTilde(a[1])) ? 0 : 1)
            case "-d":
                var isDir: ObjCBool = false
                FileManager.default.fileExists(atPath: expandTilde(a[1]), isDirectory: &isDir)
                return ("", isDir.boolValue ? 0 : 1)
            case "-e": return ("", FileManager.default.fileExists(atPath: expandTilde(a[1])) ? 0 : 1)
            case "-z": return ("", a[1].isEmpty ? 0 : 1)
            case "-n": return ("", !a[1].isEmpty ? 0 : 1)
            case "-r": return ("", FileManager.default.isReadableFile(atPath: expandTilde(a[1])) ? 0 : 1)
            case "-w": return ("", FileManager.default.isWritableFile(atPath: expandTilde(a[1])) ? 0 : 1)
            case "-x": return ("", FileManager.default.isExecutableFile(atPath: expandTilde(a[1])) ? 0 : 1)
            default: return ("", 1)
            }
        }
        if a.count == 3 {
            switch a[1] {
            case "=", "==": return ("", a[0] == a[2] ? 0 : 1)
            case "!=": return ("", a[0] != a[2] ? 0 : 1)
            case "-eq": return ("", Int(a[0]) == Int(a[2]) ? 0 : 1)
            case "-ne": return ("", Int(a[0]) != Int(a[2]) ? 0 : 1)
            case "-lt": return ("", (Int(a[0]) ?? 0) < (Int(a[2]) ?? 0) ? 0 : 1)
            case "-le": return ("", (Int(a[0]) ?? 0) <= (Int(a[2]) ?? 0) ? 0 : 1)
            case "-gt": return ("", (Int(a[0]) ?? 0) > (Int(a[2]) ?? 0) ? 0 : 1)
            case "-ge": return ("", (Int(a[0]) ?? 0) >= (Int(a[2]) ?? 0) ? 0 : 1)
            default: return ("", 1)
            }
        }
        return ("", 1)
    }

    private static func cmdExpr(_ args: [String]) -> (String, Int32) {
        if args.count == 3, let a = Int(args[0]), let b = Int(args[2]) {
            switch args[1] {
            case "+": return ("\(a + b)", 0)
            case "-": return ("\(a - b)", 0)
            case "*": return ("\(a * b)", 0)
            case "/": return (b != 0 ? "\(a / b)" : "expr: division by zero", b != 0 ? 0 : 1)
            case "%": return (b != 0 ? "\(a % b)" : "expr: division by zero", b != 0 ? 0 : 1)
            default: break
            }
        }
        return ("0", 1)
    }

    private static func cmdSeq(_ args: [String]) -> (String, Int32) {
        var first = 1, step = 1, last = 1
        switch args.count {
        case 1: last = Int(args[0]) ?? 1
        case 2: first = Int(args[0]) ?? 1; last = Int(args[1]) ?? 1
        case 3: first = Int(args[0]) ?? 1; step = Int(args[1]) ?? 1; last = Int(args[2]) ?? 1
        default: return ("seq: missing operand", 1)
        }
        guard step != 0 else { return ("seq: zero step", 1) }
        var out: [String] = []
        var i = first
        while (step > 0 && i <= last) || (step < 0 && i >= last) {
            out.append("\(i)"); i += step
            if out.count > 10000 { out.append("[truncated]"); break }
        }
        return (out.joined(separator: "\n"), 0)
    }

    private static func cmdYes(_ args: [String]) -> (String, Int32) {
        let word = args.isEmpty ? "y" : args.joined(separator: " ")
        return (Array(repeating: word, count: 100).joined(separator: "\n") + "\n[truncated — yes runs forever]", 0)
    }

    private static func cmdRev(_ args: [String], stdin: String?) -> (String, Int32) {
        let text = args.isEmpty ? (stdin ?? "") :
            (FileManager.default.contents(atPath: expandTilde(args[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "")
        let lines = text.components(separatedBy: "\n")
        return (lines.map { String($0.reversed()) }.joined(separator: "\n"), 0)
    }

    private static func cmdMd5(_ args: [String]) -> (String, Int32) {
        guard let f = args.first else { return ("md5: missing file", 1) }
        guard let data = FileManager.default.contents(atPath: expandTilde(f)) else {
            return ("md5: \(f): No such file", 1)
        }
        // Simple hash using CC_MD5 via CommonCrypto (available on iOS)
        var digest = [UInt8](repeating: 0, count: 16)
        _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return ("MD5 (\(f)) = \(hex)", 0)
    }

    private static func cmdShasum(_ args: [String]) -> (String, Int32) {
        let files = args.filter { !$0.hasPrefix("-") }
        guard let f = files.first else { return ("shasum: missing file", 1) }
        guard let data = FileManager.default.contents(atPath: expandTilde(f)) else {
            return ("shasum: \(f): No such file", 1)
        }
        var digest = [UInt8](repeating: 0, count: 20)
        _ = data.withUnsafeBytes { CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest) }
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return ("\(hex)  \(f)", 0)
    }

    private static func cmdXxd(_ args: [String]) -> (String, Int32) {
        let files = args.filter { !$0.hasPrefix("-") }
        guard let f = files.first else { return ("xxd: missing file", 1) }
        guard let data = FileManager.default.contents(atPath: expandTilde(f)) else {
            return ("xxd: \(f): No such file", 1)
        }
        let limit = min(data.count, 256)
        var output = ""
        for offset in stride(from: 0, to: limit, by: 16) {
            let end = min(offset + 16, limit)
            let hexPart = data[offset..<end].map { String(format: "%02x", $0) }.joined(separator: " ")
            let asciiPart = data[offset..<end].map { (0x20...0x7e).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
            output += String(format: "%08x: %-48s  %@\n", offset, hexPart, asciiPart)
        }
        if data.count > limit { output += "[showing first \(limit) of \(data.count) bytes]" }
        return (output, 0)
    }

    private static func cmdBase64(_ args: [String], stdin: String?) -> (String, Int32) {
        let decode = args.contains("-d") || args.contains("-D") || args.contains("--decode")
        let files = args.filter { !$0.hasPrefix("-") }
        if decode {
            let input = files.isEmpty ? (stdin ?? "") :
                (FileManager.default.contents(atPath: expandTilde(files[0])).flatMap { String(data: $0, encoding: .utf8) } ?? "")
            guard let data = Data(base64Encoded: input.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                return ("base64: invalid input", 1)
            }
            return (String(data: data, encoding: .utf8) ?? "(binary data, \(data.count) bytes)", 0)
        }
        // Encode
        let input: Data
        if let f = files.first {
            guard let d = FileManager.default.contents(atPath: expandTilde(f)) else {
                return ("base64: \(f): No such file", 1)
            }
            input = d
        } else {
            input = (stdin ?? "").data(using: .utf8) ?? Data()
        }
        return (input.base64EncodedString(), 0)
    }

    private static func cmdStrings(_ args: [String]) -> (String, Int32) {
        let files = args.filter { !$0.hasPrefix("-") }
        guard let f = files.first else { return ("strings: missing file", 1) }
        guard let data = FileManager.default.contents(atPath: expandTilde(f)) else {
            return ("strings: \(f): No such file", 1)
        }
        var results: [String] = []
        var current = ""
        for byte in data {
            if byte >= 0x20 && byte < 0x7f {
                current.append(Character(UnicodeScalar(byte)))
            } else {
                if current.count >= 4 { results.append(current) }
                current = ""
            }
            if results.count > 500 { results.append("[truncated]"); break }
        }
        if current.count >= 4 { results.append(current) }
        return (results.joined(separator: "\n"), 0)
    }

    private static func cmdXargs(_ args: [String], stdin: String?) -> (String, Int32) {
        // Simple xargs: run command with stdin lines as arguments
        guard !args.isEmpty else { return ("xargs: missing command", 1) }
        let cmd = args.joined(separator: " ")
        let lines = (stdin ?? "").components(separatedBy: "\n").filter { !$0.isEmpty }
        var output: [String] = []
        for line in lines {
            let fullCmd = "\(cmd) \(line)"
            if let result = BuiltinShell.exec(fullCmd) {
                if !result.output.isEmpty { output.append(result.output) }
            }
        }
        return (output.joined(separator: "\n"), 0)
    }
}
