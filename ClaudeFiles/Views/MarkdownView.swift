import SwiftUI

/// Lightweight markdown renderer: headers, bold/italic, inline code,
/// fenced code blocks (with copy button), bullet & numbered lists,
/// blockquotes, and horizontal rules.
struct MarkdownView: View {
    let text: String

    init(_ text: String) { self.text = text }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(Array(blocks.enumerated()), id: \.offset) { _, block in
                blockView(block)
            }
        }
    }

    // MARK: - Block model

    private enum Block {
        case heading(level: Int, text: String)
        case paragraph(String)
        case codeBlock(language: String, code: String)
        case bulletList([String])
        case numberList([String])
        case quote(String)
        case rule
        case table(headers: [String], rows: [[String]])
    }

    private var blocks: [Block] {
        var result: [Block] = []
        let lines = text.components(separatedBy: "\n")
        var i = 0

        while i < lines.count {
            let line = lines[i]

            // Fenced code block
            if line.hasPrefix("```") {
                let lang = String(line.dropFirst(3)).trimmingCharacters(in: .whitespaces)
                var code: [String] = []
                i += 1
                while i < lines.count && !lines[i].hasPrefix("```") { code.append(lines[i]); i += 1 }
                result.append(.codeBlock(language: lang, code: code.joined(separator: "\n")))
                i += 1; continue
            }

            // Headings
            if line.hasPrefix("### ") { result.append(.heading(level: 3, text: String(line.dropFirst(4)))); i += 1; continue }
            if line.hasPrefix("## ")  { result.append(.heading(level: 2, text: String(line.dropFirst(3)))); i += 1; continue }
            if line.hasPrefix("# ")   { result.append(.heading(level: 1, text: String(line.dropFirst(2)))); i += 1; continue }

            // Horizontal rule
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "---" || trimmed == "***" || trimmed == "___" {
                result.append(.rule); i += 1; continue
            }

            // Bullet list
            if line.hasPrefix("- ") || line.hasPrefix("* ") {
                var items: [String] = []
                while i < lines.count && (lines[i].hasPrefix("- ") || lines[i].hasPrefix("* ")) {
                    items.append(String(lines[i].dropFirst(2))); i += 1
                }
                result.append(.bulletList(items)); continue
            }

            // Numbered list
            if let r = line.range(of: #"^\d+\.\s"#, options: .regularExpression), r.lowerBound == line.startIndex {
                var items: [String] = []
                while i < lines.count,
                      let r2 = lines[i].range(of: #"^\d+\.\s"#, options: .regularExpression),
                      r2.lowerBound == lines[i].startIndex {
                    items.append(String(lines[i][r2.upperBound...])); i += 1
                }
                result.append(.numberList(items)); continue
            }

            // Blockquote
            if line.hasPrefix("> ") {
                var quote: [String] = []
                while i < lines.count && lines[i].hasPrefix("> ") { quote.append(String(lines[i].dropFirst(2))); i += 1 }
                result.append(.quote(quote.joined(separator: "\n"))); continue
            }

            // Table: detect "|" rows followed by a separator row like |---|---|
            if line.contains("|") && i + 1 < lines.count {
                let nextLine = lines[i + 1].trimmingCharacters(in: .whitespaces)
                let isSep = nextLine.contains("|") && nextLine.contains("-")
                    && nextLine.replacingOccurrences(of: "|", with: "")
                        .replacingOccurrences(of: "-", with: "")
                        .replacingOccurrences(of: ":", with: "")
                        .replacingOccurrences(of: " ", with: "")
                        .isEmpty
                if isSep {
                    let headers = Self.parseTableRow(line)
                    i += 2 // skip header + separator
                    var rows: [[String]] = []
                    while i < lines.count && lines[i].contains("|") {
                        let cells = Self.parseTableRow(lines[i])
                        if cells.isEmpty { break }
                        rows.append(cells)
                        i += 1
                    }
                    result.append(.table(headers: headers, rows: rows))
                    continue
                }
            }

            // Blank line → skip
            if line.isEmpty { i += 1; continue }

            // Paragraph: combine consecutive non-special lines
            var para: [String] = [line]; i += 1
            while i < lines.count {
                let l = lines[i]
                if l.isEmpty || l.hasPrefix("#") || l.hasPrefix("```")
                    || l.hasPrefix("- ") || l.hasPrefix("* ") || l.hasPrefix("> ") { break }
                if l.range(of: #"^\d+\.\s"#, options: .regularExpression) != nil { break }
                para.append(l); i += 1
            }
            result.append(.paragraph(para.joined(separator: " ")))
        }
        return result
    }

    // MARK: - Block rendering

    @ViewBuilder
    private func blockView(_ block: Block) -> some View {
        switch block {
        case .heading(let level, let text):
            Text(inline(text))
                .font(level == 1 ? .title2.bold() : level == 2 ? .title3.bold() : .headline)
                .padding(.top, 2)

        case .paragraph(let s):
            Text(inline(s)).fixedSize(horizontal: false, vertical: true)

        case .codeBlock(let lang, let code):
            CodeBlockView(code: code, language: lang)

        case .bulletList(let items):
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    HStack(alignment: .top, spacing: 8) {
                        Text("•").foregroundStyle(.secondary)
                        Text(inline(item)).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

        case .numberList(let items):
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(items.enumerated()), id: \.offset) { idx, item in
                    HStack(alignment: .top, spacing: 8) {
                        Text("\(idx + 1).").foregroundStyle(.secondary).frame(minWidth: 20, alignment: .trailing)
                        Text(inline(item)).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

        case .quote(let s):
            HStack(alignment: .top, spacing: 0) {
                Rectangle().fill(Color.accentColor.opacity(0.5)).frame(width: 3)
                Text(inline(s))
                    .foregroundStyle(.secondary)
                    .padding(.leading, 10)
                    .fixedSize(horizontal: false, vertical: true)
            }

        case .rule:
            Divider().padding(.vertical, 4)

        case .table(let headers, let rows):
            TableBlockView(headers: headers, rows: rows)
        }
    }

    // MARK: - Table helpers

    private static func parseTableRow(_ line: String) -> [String] {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let stripped = trimmed.hasPrefix("|") ? String(trimmed.dropFirst()) : trimmed
        let cleaned = stripped.hasSuffix("|") ? String(stripped.dropLast()) : stripped
        return cleaned.components(separatedBy: "|").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    // MARK: - Inline formatting via AttributedString markdown

    private func inline(_ s: String) -> AttributedString {
        if let attr = try? AttributedString(
            markdown: s,
            options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        ) { return attr }
        return AttributedString(s)
    }
}

// MARK: - Table block

private struct TableBlockView: View {
    let headers: [String]
    let rows: [[String]]

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            VStack(alignment: .leading, spacing: 0) {
                // Header row
                HStack(spacing: 0) {
                    ForEach(Array(headers.enumerated()), id: \.offset) { idx, header in
                        Text(header)
                            .font(.footnote.bold())
                            .lineLimit(2)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 8)
                            .frame(minWidth: 80, alignment: .leading)
                        if idx < headers.count - 1 {
                            Divider()
                        }
                    }
                }
                .background(Color(.tertiarySystemBackground))

                Divider()

                // Data rows
                ForEach(Array(rows.enumerated()), id: \.offset) { rowIdx, row in
                    HStack(spacing: 0) {
                        ForEach(Array(row.enumerated()), id: \.offset) { colIdx, cell in
                            Text(cell)
                                .font(.footnote)
                                .lineLimit(3)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .frame(minWidth: 80, alignment: .leading)
                            if colIdx < row.count - 1 {
                                Divider()
                            }
                        }
                    }
                    if rowIdx < rows.count - 1 {
                        Divider()
                    }
                }
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(.separator), lineWidth: 0.5))
    }
}

// MARK: - Code block with copy button

struct CodeBlockView: View {
    let code:     String
    let language: String
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(language.isEmpty ? "code" : language)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
                Button {
                    UIPasteboard.general.string = code
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                } label: {
                    Image(systemName: copied ? "checkmark" : "doc.on.doc")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(Color(.tertiarySystemBackground))

            ScrollView(.horizontal, showsIndicators: false) {
                Text(code)
                    .font(.system(.footnote, design: .monospaced))
                    .padding(10)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .background(Color(.secondarySystemBackground))
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(.separator), lineWidth: 0.5))
    }
}
