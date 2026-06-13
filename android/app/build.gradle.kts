plugins {
    id("com.android.application")
}

android {
    namespace = "dev.rknchecker.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.rknchecker.android"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }
}
