import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val validationBuild = providers.gradleProperty("peerwardValidation").orNull == "true"

val releaseKeystorePath = providers.environmentVariable("PEERWARD_ANDROID_KEYSTORE").orNull
val releaseKeyAlias = providers.environmentVariable("PEERWARD_ANDROID_KEY_ALIAS").orNull
val releaseStorePassword = providers.environmentVariable("PEERWARD_ANDROID_STORE_PASSWORD").orNull
val releaseKeyPassword = providers.environmentVariable("PEERWARD_ANDROID_KEY_PASSWORD").orNull
val releaseSigningConfigured = listOf(
    releaseKeystorePath,
    releaseKeyAlias,
    releaseStorePassword,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }
val releasePackagingRequested = gradle.startParameter.taskNames.any { requested ->
    val task = requested.substringAfterLast(':')
    task in setOf("build", "assemble", "bundle", "lint", "check") ||
        (task.endsWith("Release") && task != "buildPeerwardNativeRelease")
}
if (releasePackagingRequested) {
    check(releaseSigningConfigured) {
        "release requires PEERWARD_ANDROID_KEYSTORE, PEERWARD_ANDROID_KEY_ALIAS, " +
            "PEERWARD_ANDROID_STORE_PASSWORD, and PEERWARD_ANDROID_KEY_PASSWORD"
    }
    check(File(requireNotNull(releaseKeystorePath)).isFile) {
        "PEERWARD_ANDROID_KEYSTORE must reference a protected signing keystore"
    }
}

android {
    namespace = "io.github.peerward.peerward"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.peerward.peerward"
        minSdk = 28
        targetSdk = 36
        versionCode = 4
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        manifestPlaceholders["peerwardAppLabel"] = "@string/app_name"
        ndk {
            abiFilters += setOf("arm64-v8a", "x86_64")
        }
    }

    buildFeatures { buildConfig = true }

    signingConfigs {
        create("release") {
            storeFile = file(releaseKeystorePath ?: ".missing-peerward-release-keystore")
            storePassword = releaseStorePassword ?: ""
            keyAlias = releaseKeyAlias ?: ""
            keyPassword = releaseKeyPassword ?: ""
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = true
        }
    }

    buildTypes {
        getByName("debug") {
            if (validationBuild) {
                applicationIdSuffix = ".validation"
                resValue("string", "validation_app_name", "Peerward Validation")
                manifestPlaceholders["peerwardAppLabel"] = "@string/validation_app_name"
            }
        }
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        disable += setOf("GradleDependency", "NewerVersionAvailable")
    }
}

val nativeDebugLibraries = layout.buildDirectory.dir("generated/peerwardJni/debug")
val nativeReleaseLibraries = layout.buildDirectory.dir("generated/peerwardJni/release")
val dioxusAssets = layout.buildDirectory.dir("generated/dioxusAssets")
val workspace = rootProject.projectDir.resolve("../..").canonicalFile
val nativeInputs = files(
    fileTree(workspace.resolve("crates")) { include("**/*.rs", "**/Cargo.toml") },
    workspace.resolve("Cargo.toml"),
    workspace.resolve("Cargo.lock"),
)
val cleanPeerwardNativeDebug by tasks.registering(Delete::class) {
    delete(nativeDebugLibraries)
}
val buildPeerwardNativeDebug by tasks.registering(Exec::class) {
    dependsOn(cleanPeerwardNativeDebug)
    workingDir(workspace)
    inputs.files(nativeInputs)
    outputs.dir(nativeDebugLibraries)
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", nativeDebugLibraries.get().asFile.absolutePath,
        "build", "--locked", "-p", "peerward-android-core",
    )
}
val cleanPeerwardNativeRelease by tasks.registering(Delete::class) {
    delete(nativeReleaseLibraries)
}
val buildPeerwardNativeRelease by tasks.registering(Exec::class) {
    dependsOn(cleanPeerwardNativeRelease)
    workingDir(workspace)
    inputs.files(nativeInputs)
    outputs.dir(nativeReleaseLibraries)
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", nativeReleaseLibraries.get().asFile.absolutePath,
        "build", "--release", "--locked", "-p", "peerward-android-core",
    )
}

val dioxusWebOutput = workspace.resolve("target/dx/peerward-android-ui/release/web/public")
val cleanDioxusUi by tasks.registering(Delete::class) {
    delete(dioxusWebOutput)
}
val buildDioxusUi by tasks.registering(Exec::class) {
    dependsOn(cleanDioxusUi)
    workingDir(workspace)
    inputs.files(
        fileTree(workspace.resolve("apps/peerward-android-ui")) { include("**/*.rs", "Cargo.toml", "Dioxus.toml") },
        fileTree(workspace.resolve("apps/peerward-ui")) { include("**/*") },
        workspace.resolve("Cargo.toml"),
        workspace.resolve("Cargo.lock"),
    )
    commandLine(
        "dx", "build", "--web", "--release", "--debug-symbols", "false",
        "--package", "peerward-android-ui", "--locked",
    )
}

val syncDioxusUi by tasks.registering(Sync::class) {
    dependsOn(buildDioxusUi)
    from(dioxusWebOutput)
    into(dioxusAssets.map { it.dir("dioxus") })
}

android.sourceSets.getByName("debug").jniLibs.srcDir(nativeDebugLibraries)
android.sourceSets.getByName("release").jniLibs.srcDir(nativeReleaseLibraries)
android.sourceSets.getByName("main").assets.srcDir(dioxusAssets)
android.sourceSets.getByName("main").assets.srcDir(workspace.resolve("third_party"))
tasks.named("preBuild").configure { dependsOn(syncDioxusUi) }
tasks.matching { it.name == "preDebugBuild" }.configureEach {
    dependsOn(buildPeerwardNativeDebug)
}
tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn(buildPeerwardNativeRelease)
}

dependencies {
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.webkit:webkit:1.12.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.zxing:core:3.5.3")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    testImplementation("org.json:json:20240303")

    androidTestImplementation("androidx.test:core-ktx:1.6.1")
    androidTestImplementation("androidx.test.ext:junit-ktx:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}
