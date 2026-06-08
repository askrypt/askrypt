package com.askrypt.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * FlutterFragmentActivity (not the default FlutterActivity) because local_auth's
 * biometric prompt requires a FragmentActivity host. Also hosts the
 * `askrypt/secure` channel (PLAN Phase 4): FLAG_SECURE toggling and
 * sensitive-flagged clipboard copies.
 */
class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "askrypt/secure")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "setSecureFlag" -> {
                        val secure = call.argument<Boolean>("secure") ?: false
                        runOnUiThread {
                            if (secure) {
                                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            } else {
                                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                            }
                        }
                        result.success(null)
                    }
                    "copySensitive" -> {
                        val text = call.argument<String>("text") ?: ""
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE)
                            as ClipboardManager
                        val clip = ClipData.newPlainText("Askrypt", text)
                        // Android 13+ hides sensitive content from the clipboard
                        // preview/clipboard history.
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            clip.description.extras = PersistableBundle().apply {
                                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                            }
                        }
                        cm.setPrimaryClip(clip)
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }
}
