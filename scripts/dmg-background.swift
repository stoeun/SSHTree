import AppKit
import CoreText
import ImageIO
import UniformTypeIdentifiers

let output = CommandLine.arguments.dropFirst().first ?? "background.png"
let scale: CGFloat = 2
let width: CGFloat = 640
let height: CGFloat = 400

guard let context = CGContext(
    data: nil,
    width: Int(width * scale),
    height: Int(height * scale),
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: CGColorSpaceCreateDeviceRGB(),
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    fputs("无法创建安装图\n", stderr)
    exit(1)
}

context.scaleBy(x: scale, y: scale)
context.setFillColor(CGColor(srgbRed: 0.09, green: 0.10, blue: 0.12, alpha: 1))
context.fill(CGRect(x: 0, y: 0, width: width, height: height))

if let glow = CGGradient(
    colorsSpace: CGColorSpaceCreateDeviceRGB(),
    colors: [
        CGColor(srgbRed: 0.12, green: 0.48, blue: 0.46, alpha: 0.55),
        CGColor(srgbRed: 0.12, green: 0.48, blue: 0.46, alpha: 0)
    ] as CFArray,
    locations: [0, 1]
) {
    context.drawRadialGradient(
        glow,
        startCenter: CGPoint(x: 320, y: 210),
        startRadius: 0,
        endCenter: CGPoint(x: 320, y: 210),
        endRadius: 280,
        options: []
    )
}

let arrow = CGMutablePath()
arrow.move(to: CGPoint(x: 268, y: 214))
arrow.addLine(to: CGPoint(x: 360, y: 214))
arrow.move(to: CGPoint(x: 338, y: 232))
arrow.addLine(to: CGPoint(x: 366, y: 214))
arrow.addLine(to: CGPoint(x: 338, y: 196))
context.addPath(arrow)
context.setStrokeColor(CGColor(srgbRed: 0.62, green: 0.88, blue: 0.82, alpha: 0.95))
context.setLineWidth(5)
context.setLineCap(.round)
context.setLineJoin(.round)
context.strokePath()

let text = "把「SSHTree」拖到“应用程序”" as CFString
let font = CTFontCreateWithName("PingFangSC-Medium" as CFString, 18, nil)
let attributes: [NSAttributedString.Key: Any] = [
    .font: font,
    .foregroundColor: NSColor(srgbRed: 0.78, green: 0.86, blue: 0.84, alpha: 1)
]
let line = CTLineCreateWithAttributedString(NSAttributedString(string: text as String, attributes: attributes))
let bounds = CTLineGetBoundsWithOptions(line, [])
context.textPosition = CGPoint(x: (width - bounds.width) / 2, y: 78)
CTLineDraw(line, context)

guard let image = context.makeImage() else {
    fputs("无法导出安装图\n", stderr)
    exit(1)
}

let url = URL(fileURLWithPath: output) as CFURL
guard let destination = CGImageDestinationCreateWithURL(url, UTType.png.identifier as CFString, 1, nil) else {
    fputs("无法写入安装图\n", stderr)
    exit(1)
}
CGImageDestinationAddImage(destination, image, [
    kCGImagePropertyDPIWidth: 144,
    kCGImagePropertyDPIHeight: 144
] as CFDictionary)
guard CGImageDestinationFinalize(destination) else {
    fputs("写入安装图失败\n", stderr)
    exit(1)
}
