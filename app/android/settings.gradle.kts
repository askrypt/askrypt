pluginManagement {
    val flutterSdkPath =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            val flutterSdkPath = properties.getProperty("flutter.sdk")
            require(flutterSdkPath != null) { "flutter.sdk not set in local.properties" }
            flutterSdkPath
        }

    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    // AGP pinned into [8.9.1, 9.0): the `flutter create` template defaulted to
    // AGP 9.0.1, but file_picker 11.x skips applying the Kotlin Android plugin
    // on AGP >= 9, so its Kotlin sources (FilePickerPlugin) never compile. The
    // floor is androidx.core 1.17.0 (pulled by Flutter 3.44.1), which requires
    // AGP >= 8.9.1 and compileSdk 36. 8.11.1 satisfies both. Gradle 8.14 +
    // Kotlin 2.2.20 are Flutter 3.44.1's minimum-supported versions.
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.20" apply false
}

include(":app")
