import Foundation

#if os(iOS)
import Darwin

// Xcode links the static Rust archive into both the app framework and the
// test bundle. Resolve hooks from the framework that executes SDK calls.
private enum FrameworkHooks {
    nonisolated(unsafe) static let handle: UnsafeMutableRawPointer = {
        let framework = Bundle.allFrameworks.first { $0.bundleURL.lastPathComponent == "RatifyProtocol.framework" }
        guard let path = framework?.executablePath, let handle = dlopen(path, RTLD_NOW) else {
            fatalError("RatifyProtocol.framework is not loaded")
        }
        return handle
    }()

    static func symbol(_ name: String) -> UnsafeMutableRawPointer {
        guard let symbol = dlsym(handle, name) else { fatalError("missing test hook \(name)") }
        return symbol
    }
}

enum TestHooks {
    static func armPanic() {
        let call = unsafeBitCast(FrameworkHooks.symbol("ratify_ffi_test_arm_panic"),
            to: (@convention(c) () -> Void).self)
        call()
    }

    static func armCallbackPanic(_ kind: UInt32) {
        let call = unsafeBitCast(FrameworkHooks.symbol("ratify_ffi_test_arm_callback_panic"),
            to: (@convention(c) (UInt32) -> Void).self)
        call(kind)
    }

    static func callbackPanicRemaining() -> UInt32 {
        let call = unsafeBitCast(FrameworkHooks.symbol("ratify_ffi_test_callback_panic_remaining"),
            to: (@convention(c) () -> UInt32).self)
        return call()
    }
}
#else
@_silgen_name("ratify_ffi_test_arm_panic")
private func ffiArmPanic()
@_silgen_name("ratify_ffi_test_arm_callback_panic")
private func ffiArmCallbackPanic(_ kind: UInt32)
@_silgen_name("ratify_ffi_test_callback_panic_remaining")
private func ffiCallbackPanicRemaining() -> UInt32

enum TestHooks {
    static func armPanic() { ffiArmPanic() }
    static func armCallbackPanic(_ kind: UInt32) { ffiArmCallbackPanic(kind) }
    static func callbackPanicRemaining() -> UInt32 { ffiCallbackPanicRemaining() }
}
#endif
