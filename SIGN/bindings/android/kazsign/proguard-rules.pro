# KAZ-SIGN ProGuard Rules

# Keep all public API
-keep class com.pqc.kazsign.** { *; }

# Keep JNI methods
-keepclasseswithmembers class * {
    native <methods>;
}

# Keep data classes
-keepclassmembers class com.pqc.kazsign.KeyPair { *; }
-keepclassmembers class com.pqc.kazsign.SignatureResult { *; }
-keepclassmembers class com.pqc.kazsign.VerificationResult { *; }
