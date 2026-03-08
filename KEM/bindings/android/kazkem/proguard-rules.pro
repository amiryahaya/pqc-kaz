# KAZ-KEM ProGuard Rules

# Keep all public API classes
-keep public class com.pqc.kazkem.KazKem { *; }
-keep public class com.pqc.kazkem.KazKemKeyPair { *; }
-keep public class com.pqc.kazkem.KazKemPublicKey { *; }
-keep public class com.pqc.kazkem.KazKemEncapsulationResult { *; }
-keep public class com.pqc.kazkem.SecurityLevel { *; }
-keep public class com.pqc.kazkem.KazKemException { *; }
-keep public class com.pqc.kazkem.NotInitializedException { *; }
-keep public class com.pqc.kazkem.InvalidParameterException { *; }

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep native bridge
-keep class com.pqc.kazkem.KazKemNative { *; }
