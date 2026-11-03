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

public enum InternalErrorKind: String, Sendable {
    case panic
    case poisoned
}

/// Run one generated-layer call and translate its failure into `RatifyError`.
func ffi<T>(_ body: () throws -> T) throws(RatifyError) -> T {
    do {
        return try body()
    } catch let e as FfiError {
        throw RatifyError(e)
    } catch {
        // The generated layer's only other failure is a caught Rust panic.
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
            self = .internal(InternalErrorKind(rawValue: kind) ?? .panic, message: message)
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
