import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)

    // `askrypt/secure` channel (PLAN Phase 4). FLAG_SECURE has no iOS analogue
    // here (a snapshot overlay could be added later); copySensitive uses an
    // expiring, device-local pasteboard item.
    let registrar = engineBridge.pluginRegistry.registrar(forPlugin: "AskryptSecure")!
    let channel = FlutterMethodChannel(
      name: "askrypt/secure", binaryMessenger: registrar.messenger())
    channel.setMethodCallHandler { call, result in
      switch call.method {
      case "setSecureFlag":
        result(nil) // no-op on iOS
      case "copySensitive":
        let text = (call.arguments as? [String: Any])?["text"] as? String ?? ""
        UIPasteboard.general.setItems(
          [["public.utf8-plain-text": text]],
          options: [
            .expirationDate: Date().addingTimeInterval(30),
            .localOnly: true,
          ])
        result(nil)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }
}
