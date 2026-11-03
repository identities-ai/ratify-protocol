import Foundation

/// Every error the SDK throws. Protocol and signing errors carry a SPEC-v2
/// §2.7 class; `internal` is reserved for a panic inside the core or a handle
/// a previous panic left unusable, and is never a protocol result.
public enum RatifyError: Error, Sendable, Equatable, CustomStringConvertible {
    case `protocol`(ErrorClass, message: String)
    case signing(ErrorClass, kind: String, message: String)
    case `internal`(InternalErrorKind, message: String)

    /// The §2.7 class, or nil for an internal error.
    public var errorClass: ErrorClass? {
        switch self {
        case let .protocol(c, _), let .signing(c, _, _): return c
        case .internal: return nil
        }
    }

    public var description: String {
        switch self {
        case let .protocol(c, m): return "\(m) (\(c.rawValue))"
        case let .signing(c, k, m): return "\(m) (\(c.rawValue), \(k))"
        case let .internal(k, m): return "internal \(k.rawValue): \(m)"
        }
    }
}

/// Why an internal error occurred. None of these is a protocol result.
public enum InternalErrorKind: String, Sendable, CaseIterable {
    /// A panic inside the core was caught at the boundary.
    case panic
    /// A handle a previous panic left unusable.
    case poisoned
    /// The operating-system random source failed.
    case randomSource = "random_source"
}

/// Run one generated-layer call and translate its failure into `RatifyError`.
func ffi<T>(_ body: () throws -> T) throws(RatifyError) -> T {
    do {
        return try body()
    } catch let e as FfiError {
        throw RatifyError(e)
    } catch {
        // Every export catches its own panics; this is UniFFI's backstop.
        throw .internal(.panic, message: "\(error)")
    }
}

extension RatifyError {
    init(_ e: FfiError) {
        switch e {
        case let .Protocol(cls, message):
            self = .protocol(ErrorClass(spelling: cls), message: message)
        case let .Signing(cls, kind, message):
            self = .signing(ErrorClass(spelling: cls), kind: kind, message: message)
        case let .Internal(kind, message):
            // The FFI layer emits only these kinds; the list is pinned by a test.
            guard let k = InternalErrorKind(rawValue: kind) else {
                preconditionFailure("FFI layer returned an unknown internal error kind \(kind)")
            }
            self = .internal(k, message: message)
        }
    }
}

extension ErrorClass {
    /// The core only emits §2.7 spellings; the class list is pinned by a test.
    init(spelling: String) {
        guard let c = ErrorClass(rawValue: spelling) else {
            preconditionFailure("core returned an unknown error class \(spelling)")
        }
        self = c
    }
}
