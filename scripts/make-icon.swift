import AppKit
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

let size = 1024
let canvas = NSRect(x: 0, y: 0, width: size, height: size)
guard let context = CGContext(
    data: nil,
    width: size,
    height: size,
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: CGColorSpaceCreateDeviceRGB(),
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    fputs("无法创建画布\n", stderr)
    exit(1)
}

let iconRect = canvas.insetBy(dx: 40, dy: 40)
let path = CGPath(roundedRect: iconRect, cornerWidth: 220, cornerHeight: 220, transform: nil)
context.addPath(path)
context.clip()

let colors = [
    CGColor(srgbRed: 0.05, green: 0.16, blue: 0.17, alpha: 1),
    CGColor(srgbRed: 0.08, green: 0.42, blue: 0.40, alpha: 1),
    CGColor(srgbRed: 0.55, green: 0.86, blue: 0.78, alpha: 1)
] as CFArray
let locations: [CGFloat] = [0, 0.55, 1]
if let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: locations) {
    context.drawLinearGradient(
        gradient,
        start: CGPoint(x: 180, y: 160),
        end: CGPoint(x: 860, y: 900),
        options: []
    )
}

context.setFillColor(CGColor(srgbRed: 0.93, green: 0.98, blue: 0.96, alpha: 0.92))
context.fill(CGRect(x: 250, y: 430, width: 524, height: 18))
context.fill(CGRect(x: 492, y: 250, width: 40, height: 198))
context.setFillColor(CGColor(srgbRed: 0.55, green: 1, blue: 0.86, alpha: 1))
context.fill(CGRect(x: 430, y: 560, width: 164, height: 210))

guard let image = context.makeImage() else {
    fputs("无法导出图标\n", stderr)
    exit(1)
}

let output = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "App/AppIcon-1024.png")
try FileManager.default.createDirectory(at: output.deletingLastPathComponent(), withIntermediateDirectories: true)
guard let destination = CGImageDestinationCreateWithURL(output as CFURL, UTType.png.identifier as CFString, 1, nil) else {
    fputs("无法写入 PNG\n", stderr)
    exit(1)
}
CGImageDestinationAddImage(destination, image, nil)
guard CGImageDestinationFinalize(destination) else {
    fputs("PNG 写入失败\n", stderr)
    exit(1)
}
print(output.path)
