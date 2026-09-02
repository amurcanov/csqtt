// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.isFile) {
    localPropertiesFile.inputStream().use { input -> localProperties.load(input) }
}

fun releaseSigningValue(name: String): String? =
    providers.gradleProperty(name).orNull
        ?: providers.environmentVariable(name).orNull
        ?: localProperties.getProperty(name)

fun requiredReleaseSigningValue(name: String): String? =
    releaseSigningValue(name)?.takeIf { it.isNotBlank() }

val releaseKeystorePath = requiredReleaseSigningValue("KEYSTORE_FILE")?.trim()
val releaseKeystoreFile = releaseKeystorePath?.let { path ->
    // Keep supporting the existing ../release.keystore convention relative to
    // the repository root, while also accepting absolute and root-relative paths.
    if (path.startsWith("../") || path.startsWith("..\\")) {
        rootProject.file(path.substring(3))
    } else {
        rootProject.file(path)
    }
}
val releaseStorePassword = requiredReleaseSigningValue("KEYSTORE_PASSWORD")
val releaseKeyAlias = requiredReleaseSigningValue("KEY_ALIAS")
val releaseKeyPassword = requiredReleaseSigningValue("KEY_PASSWORD")
val releaseSigningProblems = mutableListOf<String>().apply {
    when {
        releaseKeystoreFile == null -> add("KEYSTORE_FILE is not configured")
        !releaseKeystoreFile.isFile -> add("the configured release keystore is unavailable")
        !releaseKeystoreFile.canRead() -> add("the configured release keystore is not readable")
    }
    if (releaseStorePassword == null) add("KEYSTORE_PASSWORD is not configured")
    if (releaseKeyAlias == null) add("KEY_ALIAS is not configured")
    if (releaseKeyPassword == null) add("KEY_PASSWORD is not configured")
}
val releaseSigningReady = releaseSigningProblems.isEmpty()

val verifyReleaseSigning = tasks.register("verifyReleaseSigning") {
    group = "verification"
    description = "Verifies that a release build has an explicit, readable signing configuration."
    inputs.property("releaseSigningProblems", releaseSigningProblems.joinToString("; "))
    doLast {
        val signingProblems = inputs.properties["releaseSigningProblems"] as String
        check(signingProblems.isEmpty()) {
            "Release signing is not configured: $signingProblems. " +
                "Provide the required values through Gradle properties, environment variables, " +
                "or an untracked local.properties file."
        }
    }
}

android {
    namespace = "com.csqtt.client"
    compileSdk = 37

    defaultConfig {
        applicationId = "csqtt.quic.amurcanov"
        minSdk = 26
        targetSdk = 37
        versionCode = 221
        versionName = "2.1.9"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        ndk {
            abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
        }
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    signingConfigs {
        create("release") {
            if (releaseSigningReady) {
                storeFile = requireNotNull(releaseKeystoreFile)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (releaseSigningReady) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += "**/libclient.so"
            keepDebugSymbols += "**/libandroidx.graphics.path.so"
            keepDebugSymbols += "**/libdatastore_shared_counter.so"
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/META-INF/DEPENDENCIES"
            excludes += "/META-INF/LICENSE.md"
            excludes += "/META-INF/NOTICE.md"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    lint {
        checkReleaseBuilds = true
        abortOnError = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add("src/main/jniLibs")
        }
    }
}

tasks.configureEach {
    val taskName = name.lowercase()
    val preparesReleaseBuild = taskName == "prereleasebuild"
    val producesReleaseArtifact = taskName.contains("release") &&
        (taskName.startsWith("assemble") ||
            taskName.startsWith("bundle") ||
            taskName.startsWith("package") ||
            taskName.startsWith("sign") ||
            taskName.startsWith("install") ||
            taskName.startsWith("publish") ||
            taskName.startsWith("upload"))
    if (preparesReleaseBuild || producesReleaseArtifact) {
        dependsOn(verifyReleaseSigning)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.19.0")
    implementation(platform("androidx.compose:compose-bom:2026.08.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.datastore:datastore-preferences:1.2.1")
    implementation("com.hierynomus:sshj:0.38.0") {
        exclude(group = "org.bouncycastle", module = "bcprov-jdk18on")
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk18on")
        exclude(group = "org.bouncycastle", module = "bcutil-jdk18on")
    }
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.85")
    implementation("org.bouncycastle:bcutil-jdk18on:1.85")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("org.mockito:mockito-core:5.23.0")
    testImplementation("org.json:json:20260814")

    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation(platform("androidx.compose:compose-bom:2026.08.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
