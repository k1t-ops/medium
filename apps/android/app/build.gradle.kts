import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.burniq.medium.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.burniq.medium.android"
        minSdk = 28
        targetSdk = 35
        versionCode = 4
        versionName = "0.0.4"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDir("src/main/jniLibs")
        }
    }
}

data class RustAndroidTarget(
    val abi: String,
    val rustTarget: String,
    val clangPrefix: String,
    val linkerEnv: String,
)

val mediumRustTargets = listOf(
    RustAndroidTarget(
        abi = "arm64-v8a",
        rustTarget = "aarch64-linux-android",
        clangPrefix = "aarch64-linux-android",
        linkerEnv = "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
    ),
    RustAndroidTarget(
        abi = "armeabi-v7a",
        rustTarget = "armv7-linux-androideabi",
        clangPrefix = "armv7a-linux-androideabi",
        linkerEnv = "CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER",
    ),
    RustAndroidTarget(
        abi = "x86",
        rustTarget = "i686-linux-android",
        clangPrefix = "i686-linux-android",
        linkerEnv = "CARGO_TARGET_I686_LINUX_ANDROID_LINKER",
    ),
    RustAndroidTarget(
        abi = "x86_64",
        rustTarget = "x86_64-linux-android",
        clangPrefix = "x86_64-linux-android",
        linkerEnv = "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER",
    ),
)

fun androidSdkDir(): File? {
    providers.environmentVariable("ANDROID_HOME").orNull
        ?.let { return file(it) }
    providers.environmentVariable("ANDROID_SDK_ROOT").orNull
        ?.let { return file(it) }

    val localPropertiesFile = rootProject.file("local.properties")
    if (localPropertiesFile.isFile) {
        val properties = Properties()
        localPropertiesFile.inputStream().use(properties::load)
        properties.getProperty("sdk.dir")
            ?.takeIf { it.isNotBlank() }
            ?.let { return file(it) }
    }

    return null
}

fun newestAndroidNdkDir(): File? {
    val sdk = androidSdkDir() ?: return null
    return sdk.resolve("ndk")
        .takeIf { it.isDirectory }
        ?.listFiles()
        ?.filter { it.isDirectory }
        ?.maxByOrNull { it.name }
}

fun ndkHostTag(): String = when {
    org.gradle.internal.os.OperatingSystem.current().isMacOsX -> "darwin-x86_64"
    org.gradle.internal.os.OperatingSystem.current().isLinux -> "linux-x86_64"
    else -> error("Unsupported Android NDK host OS")
}

fun runCheckedCommand(workingDir: File, command: List<String>, environment: Map<String, String> = emptyMap()) {
    val process = ProcessBuilder(command)
        .directory(workingDir)
        .redirectErrorStream(true)
        .also { builder -> builder.environment().putAll(environment) }
        .start()
    process.inputStream.bufferedReader().useLines { lines ->
        lines.forEach { logger.lifecycle(it) }
    }
    val exitCode = process.waitFor()
    check(exitCode == 0) { "Command failed ($exitCode): ${command.joinToString(" ")}" }
}

val buildMediumAndroidNetstack by tasks.registering {
    group = "build"
    description = "Builds Rust medium-android-netstack JNI library for Android ABIs when the NDK is installed."

    doLast {
        val ndkDir = newestAndroidNdkDir()
            ?: error("Android NDK is required to build Medium netstack. Install it in Android Studio SDK Manager.")
        val workspaceDir = rootProject.projectDir.resolve("../..").canonicalFile
        val toolchainBin = ndkDir.resolve("toolchains/llvm/prebuilt/${ndkHostTag()}/bin")
        val api = android.defaultConfig.minSdk ?: 28

        mediumRustTargets.forEach { target ->
            val linker = toolchainBin.resolve("${target.clangPrefix}${api}-clang")
            if (!linker.isFile) {
                error("Missing Android linker ${linker.absolutePath}; cannot build ${target.abi}.")
            }

            runCheckedCommand(workspaceDir, listOf("rustup", "target", "add", target.rustTarget))
            runCheckedCommand(
                workingDir = workspaceDir,
                environment = mapOf(
                    target.linkerEnv to linker.absolutePath,
                    "CC_${target.rustTarget.replace('-', '_')}" to linker.absolutePath,
                    "CXX_${target.rustTarget.replace('-', '_')}" to toolchainBin.resolve("${target.clangPrefix}${api}-clang++").absolutePath,
                    "AR_${target.rustTarget.replace('-', '_')}" to toolchainBin.resolve("llvm-ar").absolutePath,
                    "PATH" to toolchainBin.absolutePath + File.pathSeparator + System.getenv("PATH").orEmpty(),
                ),
                command = listOf(
                    "cargo",
                    "build",
                    "--package",
                    "medium-android-netstack",
                    "--target",
                    target.rustTarget,
                    "--release",
                ),
            )

            copy {
                from(workspaceDir.resolve("target/${target.rustTarget}/release/libmedium_android_netstack.so"))
                into(projectDir.resolve("src/main/jniLibs/${target.abi}"))
            }
        }
    }
}

tasks.named("preBuild") {
    dependsOn(buildMediumAndroidNetstack)
}

tasks.matching {
    it.name in setOf(
        "mergeDebugJniLibFolders",
        "mergeReleaseJniLibFolders",
        "mergeDebugNativeLibs",
        "mergeReleaseNativeLibs",
        "packageDebug",
        "packageRelease",
        "installDebug",
    )
}.configureEach {
    dependsOn(buildMediumAndroidNetstack)
}

dependencies {
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.material3:material3:1.3.1")
    testImplementation("junit:junit:4.13.2")
}
