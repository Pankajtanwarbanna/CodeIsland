import Foundation

/// A conservative, explainable assessment for permission prompts.
///
/// This classifier is display-only. It must never be used as an authorization
/// decision: shell aliases, scripts, quoting, and runtime context can change a
/// command's real effect.
public enum ToolRiskLevel: String, CaseIterable, Sendable {
    case low
    case medium
    case high
    case critical
    case unknown
}

public struct ToolRiskAssessment: Equatable, Sendable {
    public let level: ToolRiskLevel
    public let summary: String
    public let evidence: [String]

    public init(level: ToolRiskLevel, summary: String, evidence: [String] = []) {
        self.level = level
        self.summary = summary
        self.evidence = evidence
    }
}

public enum ToolRiskClassifier {
    /// Returns a display-only risk hint for a tool permission request.
    public static func assess(tool: String, input: [String: Any]?) -> ToolRiskAssessment {
        let normalizedTool = tool.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if let command = command(from: input), !command.isEmpty {
            return assessCommand(command)
        }

        let path = filePath(from: input)

        if isReadOnlyTool(normalizedTool), let path, isSensitivePath(path) {
            return ToolRiskAssessment(
                level: .high,
                summary: "reads sensitive data",
                evidence: [path]
            )
        }

        if isReadOnlyTool(normalizedTool) {
            return ToolRiskAssessment(
                level: .low,
                summary: "read-only operation",
                evidence: ["tool is normally non-mutating"]
            )
        }

        if isFileMutationTool(normalizedTool) {
            if let path, isSensitivePath(path) {
                return ToolRiskAssessment(
                    level: .high,
                    summary: "changes a sensitive path",
                    evidence: [path]
                )
            }
            return ToolRiskAssessment(
                level: .medium,
                summary: "changes local files",
                evidence: path.map { [$0] } ?? []
            )
        }

        if normalizedTool.contains("delete") || normalizedTool.contains("remove") {
            return ToolRiskAssessment(
                level: .high,
                summary: "destructive tool action",
                evidence: [tool]
            )
        }

        return ToolRiskAssessment(
            level: .unknown,
            summary: "effect needs review",
            evidence: ["no reliable rule matched"]
        )
    }

    public static func assessCommand(_ command: String) -> ToolRiskAssessment {
        let value = command
            .replacingOccurrences(of: "\\\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = value.lowercased()

        let rules: [(ToolRiskLevel, String, [String])] = [
            (.critical, "can erase a disk or root filesystem", [
                #"\brm\b(?=[^;\n|&]*\s(?:-[a-z]*r[a-z]*|--recursive)\b)(?=[^;\n|&]*\s(?:-[a-z]*f[a-z]*|--force)\b)[^;\n|&]*\s(?:--\s+)?["']?(?:/+|/+\*|~|\$home)["']?(?:\s|$)"#,
                #"\b(?:mkfs(?:\.[a-z0-9]+)?|diskutil\s+erase|fdisk)\b"#,
                #"\bdd\b[^\n;|&]*\bof\s*=\s*/dev/"#
            ]),
            (.critical, "can expose credentials or execute untrusted remote code", [
                #"\b(?:curl|wget)\b[^\n]*(?:\||\$\()[^\n]*(?:sh|bash|zsh)\b"#,
                #"\b(?:cat|tar|zip|scp|rsync|curl)\b[^\n]*(?:\.ssh|\.aws|\.env\b|credentials|id_rsa|id_ed25519)"#
            ]),
            (.high, "destructive filesystem operation", [
                #"\brm\b(?=[^;\n|&]*\s(?:-[a-z]*r[a-z]*|--recursive)\b)"#,
                #"\bfind\b[^\n]*(?:-delete|-exec\s+rm)\b"#,
                #"\bchmod\b(?=[^;\n|&]*\s(?:-[a-z]*r[a-z]*|--recursive)\b)"#,
                #"\bchown\b(?=[^;\n|&]*\s(?:-[a-z]*r[a-z]*|--recursive)\b)"#
            ]),
            (.high, "can discard version-control history or changes", [
                #"\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f|push\b[^\n]*(?:--force(?:-with-lease)?|-f\b))"#,
                #"\bhg\s+(?:strip|rollback)\b"#
            ]),
            (.high, "destructive infrastructure or database action", [
                #"\bterraform\s+destroy\b"#,
                #"\bkubectl\s+delete\b"#,
                #"\b(?:drop\s+(?:database|schema|table)|truncate\s+table)\b"#,
                #"\b(?:shutdown|reboot|poweroff|halt)\b"#
            ]),
            (.medium, "publishes or changes remote state", [
                #"\bgit\s+push\b"#,
                #"\b(?:npm|pnpm|yarn|cargo|twine|gem)\s+publish\b"#,
                #"\b(?:gh\s+(?:pr\s+merge|release\s+create)|docker\s+push)\b"#,
                #"\b(?:curl|wget)\b[^\n]*(?:-x\s*(?:post|put|patch|delete)|--request\s+(?:post|put|patch|delete)|--data(?:-binary|-raw)?\b)"#
            ]),
            (.medium, "installs software or changes the machine", [
                #"\b(?:sudo|su)\b"#,
                #"\b(?:apt(?:-get)?|brew|dnf|yum|pacman)\s+(?:install|remove|upgrade|update)\b"#,
                #"\b(?:npm|pnpm|yarn|pip|pip3|uv|cargo|gem)\s+(?:install|add|remove|uninstall|update)\b"#,
                #"\b(?:kill|killall|pkill)\b"#,
                #"\b(?:docker|podman)\s+(?:rm|rmi|stop|kill|system\s+prune)\b"#
            ])
        ]

        for (level, summary, patterns) in rules {
            if let pattern = patterns.first(where: { matches($0, in: lower) }) {
                return ToolRiskAssessment(level: level, summary: summary, evidence: [matchedFragment(pattern, in: lower) ?? value])
            }
        }

        // Keep this allow-list deliberately narrow. Test, build, package-manager,
        // script, and file-content commands can execute repository code or expose
        // secrets, so they remain unknown unless a higher-risk rule matches.
        let lowRiskPatterns = [
            #"^\s*(?:pwd|whoami|date|ls|git\s+status)\b"#
        ]
        if lowRiskPatterns.contains(where: { matches($0, in: lower) }) && !containsShellComposition(lower) {
            return ToolRiskAssessment(
                level: .low,
                summary: "appears read-only or locally verifiable",
                evidence: [String(value.prefix(120))]
            )
        }

        return ToolRiskAssessment(
            level: .unknown,
            summary: "command effect needs review",
            evidence: [String(value.prefix(120))]
        )
    }

    private static func command(from input: [String: Any]?) -> String? {
        guard let input else { return nil }
        for key in ["command", "CommandLine", "cmd", "script"] {
            if let value = input[key] as? String {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { return trimmed }
            }
        }
        return nil
    }

    private static func filePath(from input: [String: Any]?) -> String? {
        guard let input else { return nil }
        for key in ["file_path", "path", "filePath", "target"] {
            if let value = input[key] as? String, !value.isEmpty { return value }
        }
        return nil
    }

    private static func isReadOnlyTool(_ tool: String) -> Bool {
        let names: Set<String> = [
            "read", "glob", "grep", "search", "websearch", "webfetch",
            "todoread", "list", "view", "inspect"
        ]
        return names.contains(tool)
    }

    private static func isFileMutationTool(_ tool: String) -> Bool {
        let names: Set<String> = [
            "write", "edit", "multiedit", "apply_patch", "patch", "create_file"
        ]
        return names.contains(tool)
    }

    private static func isSensitivePath(_ path: String) -> Bool {
        let lower = path
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\\", with: "/")
            .lowercased()
        return lower == ".env"
            || lower == "credentials"
            || lower == ".ssh"
            || lower == "~/.ssh"
            || lower == ".aws"
            || lower == "~/.aws"
            || lower == "/etc"
            || lower == "/system"
            || lower == "/usr"
            || lower.hasPrefix(".ssh/")
            || lower.hasPrefix("~/.ssh/")
            || lower.hasPrefix(".aws/")
            || lower.hasPrefix("~/.aws/")
            || lower.hasPrefix("/etc/")
            || lower.hasPrefix("/system/")
            || lower.hasPrefix("/usr/")
            || lower.contains("/.ssh/")
            || lower.contains("/.aws/")
            || lower.hasSuffix("/.ssh")
            || lower.hasSuffix("/.aws")
            || lower.hasSuffix("/.env")
            || lower.hasSuffix("/credentials")
    }

    private static func containsShellComposition(_ command: String) -> Bool {
        command.contains(";")
            || command.contains("&&")
            || command.contains("||")
            || command.contains("&")
            || command.contains("|")
            || command.contains(">")
            || command.contains("<")
            || command.contains("`")
            || command.contains("$(")
            || command.contains("-exec")
            || command.contains("\n")
            || command.contains("\r")
    }

    private static func matches(_ pattern: String, in value: String) -> Bool {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return false }
        return regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)) != nil
    }

    private static func matchedFragment(_ pattern: String, in value: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
              let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
              let range = Range(match.range, in: value) else { return nil }
        return String(value[range].prefix(120))
    }
}
