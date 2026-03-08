# KAZ-SIGN Consumer ProGuard Rules
# These rules are automatically applied to apps that use this library

# Keep all public API classes and methods
-keep class com.pqc.kazsign.SecurityLevel { *; }
-keep class com.pqc.kazsign.KazSigner { *; }
-keep class com.pqc.kazsign.KazSignException { *; }
-keep class com.pqc.kazsign.KazSignException$ErrorCode { *; }
-keep class com.pqc.kazsign.KeyPair { *; }
-keep class com.pqc.kazsign.SignatureResult { *; }
-keep class com.pqc.kazsign.VerificationResult { *; }

# Keep extension functions
-keep class com.pqc.kazsign.ExtensionsKt { *; }
-keep class com.pqc.kazsign.KazSignerKt { *; }
