import AppKit
import HarborKit
import SwiftUI

enum HarborPalette {
    static let accent = Color(red: 0.12, green: 0.55, blue: 0.50)
    static let ink = Color(red: 0.075, green: 0.086, blue: 0.098)
    static let inkRaised = Color(red: 0.12, green: 0.135, blue: 0.15)
    static let inkNS = NSColor(srgbRed: 0.075, green: 0.086, blue: 0.098, alpha: 1)
    static let textNS = NSColor(srgbRed: 0.86, green: 0.89, blue: 0.86, alpha: 1)
}

extension TagColor {
    var color: Color {
        switch self {
        case .teal: Color(red: 0.15, green: 0.62, blue: 0.58)
        case .blue: Color(red: 0.20, green: 0.48, blue: 0.86)
        case .indigo: Color(red: 0.35, green: 0.38, blue: 0.85)
        case .purple: Color(red: 0.55, green: 0.36, blue: 0.78)
        case .pink: Color(red: 0.84, green: 0.36, blue: 0.55)
        case .red: Color(red: 0.82, green: 0.28, blue: 0.28)
        case .orange: Color(red: 0.88, green: 0.48, blue: 0.20)
        case .green: Color(red: 0.24, green: 0.62, blue: 0.36)
        }
    }

    var nsColor: NSColor {
        switch self {
        case .teal: NSColor(srgbRed: 0.15, green: 0.62, blue: 0.58, alpha: 1)
        case .blue: NSColor(srgbRed: 0.20, green: 0.48, blue: 0.86, alpha: 1)
        case .indigo: NSColor(srgbRed: 0.35, green: 0.38, blue: 0.85, alpha: 1)
        case .purple: NSColor(srgbRed: 0.55, green: 0.36, blue: 0.78, alpha: 1)
        case .pink: NSColor(srgbRed: 0.84, green: 0.36, blue: 0.55, alpha: 1)
        case .red: NSColor(srgbRed: 0.82, green: 0.28, blue: 0.28, alpha: 1)
        case .orange: NSColor(srgbRed: 0.88, green: 0.48, blue: 0.20, alpha: 1)
        case .green: NSColor(srgbRed: 0.24, green: 0.62, blue: 0.36, alpha: 1)
        }
    }
}

enum HarborFormat {
    static func relative(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = Locale(identifier: "zh_CN")
        formatter.unitsStyle = .short
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    static func dateTime(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .shortened)
    }
}

func harborMonogram(_ name: String) -> String {
    let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let character = trimmed.first else { return "?" }
    return String(character).uppercased()
}

extension View {
    @ViewBuilder
    func harborPrimary() -> some View {
        if #available(macOS 26.0, *) {
            self.buttonStyle(.glassProminent)
        } else {
            self.buttonStyle(.borderedProminent)
        }
    }

    @ViewBuilder
    func harborGlassButton() -> some View {
        if #available(macOS 26.0, *) {
            self.buttonStyle(.glass)
        } else {
            self.buttonStyle(.bordered)
        }
    }

    @ViewBuilder
    func harborCard() -> some View {
        if #available(macOS 26.0, *) {
            self.glassEffect(.regular.interactive(), in: RoundedRectangle(cornerRadius: 28, style: .continuous))
        } else {
            self.background(.regularMaterial, in: RoundedRectangle(cornerRadius: 28, style: .continuous))
        }
    }
}
