# JNA and the generated FFI layer are reached reflectively.
-keep class com.sun.jna.** { *; }
-keep class com.ratifyprotocol.internal.ffi.** { *; }
-dontwarn java.awt.**
