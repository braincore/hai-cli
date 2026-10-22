// Secure Enclave helpers for hai (macOS only).
//
// Exposes a tiny C ABI consumed by `src/feature/macos_se.rs`.
//
// Scheme (ECIES-like):
//   * A P-256 key-agreement key is generated inside the Secure Enclave with an
//     access-control policy of `privateKeyUsage + userPresence` (Touch ID with
//     system password fallback). Only an opaque, device-bound handle
//     (`dataRepresentation`) leaves the enclave; hai stores it on disk.
//   * Encryption only needs the public key, so it never prompts:
//       eph = random P-256 key
//       k   = HKDF-SHA256(ECDH(eph, pub), salt = eph_pub || pub, info = INFO)
//       out = VERSION || eph_pub(65) || AES-256-GCM(k).combined
//   * Decryption performs ECDH inside the enclave and therefore requires user
//     presence. A single LAContext is shared for the life of the process so
//     that the user authenticates at most once per hai session.
//
// No keychain items are created, so no entitlements / provisioning profile /
// app bundle are required.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let VERSION: UInt8 = 1
private let INFO = Data("hai-se-vault-v1".utf8)

// Result codes (keep in sync with macos_se.rs)
private let HAI_SE_OK: Int32 = 0
private let HAI_SE_CANCELLED: Int32 = 1
private let HAI_SE_AUTH_FAILED: Int32 = 2
private let HAI_SE_INVALID_KEY: Int32 = 3
private let HAI_SE_BAD_INPUT: Int32 = 4
private let HAI_SE_UNAVAILABLE: Int32 = 5
private let HAI_SE_OTHER: Int32 = 6

private let ctxLock = NSLock()
nonisolated(unsafe) private var sharedContext: LAContext? = nil

private func context(reason: String) -> LAContext {
    ctxLock.lock()
    defer { ctxLock.unlock() }
    if let ctx = sharedContext {
        return ctx
    }
    let ctx = LAContext()
    ctx.localizedReason = reason
    sharedContext = ctx
    return ctx
}

private func writeOut(
    _ data: Data,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) {
    let buf = malloc(max(data.count, 1))!.assumingMemoryBound(to: UInt8.self)
    data.copyBytes(to: buf, count: data.count)
    outPtr.pointee = buf
    outLen.pointee = data.count
}

private func classify(_ error: Error) -> Int32 {
    let ns = error as NSError
    if ns.domain == LAErrorDomain {
        switch ns.code {
        case LAError.userCancel.rawValue, LAError.appCancel.rawValue,
            LAError.systemCancel.rawValue, LAError.userFallback.rawValue,
            LAError.notInteractive.rawValue:
            return HAI_SE_CANCELLED
        default:
            return HAI_SE_AUTH_FAILED
        }
    }
    // Errors from the enclave surface as OSStatus / CryptoKit errors. Walk
    // underlying errors looking for an LAError.
    if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? Error {
        let c = classify(underlying)
        if c != HAI_SE_OTHER { return c }
    }
    if ns.domain == NSOSStatusErrorDomain {
        if ns.code == Int(errSecUserCanceled) { return HAI_SE_CANCELLED }
        if ns.code == Int(errSecAuthFailed) { return HAI_SE_AUTH_FAILED }
    }
    return HAI_SE_OTHER
}

private func describe(_ error: Error) -> String {
    let ns = error as NSError
    var s = "\(ns.domain) \(ns.code): \(ns.localizedDescription)"
    if let u = ns.userInfo[NSUnderlyingErrorKey] as? Error {
        s += " <- " + describe(u)
    }
    return s
}

private let errLock = NSLock()
nonisolated(unsafe) private var lastErrorMsg: String = ""

private func setLastError(_ msg: String) {
    errLock.lock()
    lastErrorMsg = msg
    errLock.unlock()
}

/// Copies the last error message into a malloc'd buffer.
@_cdecl("hai_se_last_error")
public func hai_se_last_error(
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) {
    errLock.lock()
    let msg = lastErrorMsg
    errLock.unlock()
    writeOut(Data(msg.utf8), outPtr, outLen)
}

@_cdecl("hai_se_free")
public func hai_se_free(_ ptr: UnsafeMutablePointer<UInt8>?) {
    free(ptr)
}

@_cdecl("hai_se_is_available")
public func hai_se_is_available() -> Bool {
    return SecureEnclave.isAvailable
}

/// Forget the shared authentication context so the next decrypt prompts.
@_cdecl("hai_se_reset_auth")
public func hai_se_reset_auth() {
    ctxLock.lock()
    sharedContext?.invalidate()
    sharedContext = nil
    ctxLock.unlock()
}

/// Generate a new enclave key. Outputs the opaque handle and the x963 public
/// key (65 bytes). Does not prompt.
@_cdecl("hai_se_create_key")
public func hai_se_create_key(
    _ outHandle: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outHandleLen: UnsafeMutablePointer<Int>,
    _ outPub: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outPubLen: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        setLastError("secure enclave unavailable")
        return HAI_SE_UNAVAILABLE
    }
    var cfErr: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &cfErr
        )
    else {
        let e = cfErr!.takeRetainedValue() as Error
        setLastError(describe(e))
        return HAI_SE_OTHER
    }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        writeOut(key.dataRepresentation, outHandle, outHandleLen)
        writeOut(key.publicKey.x963Representation, outPub, outPubLen)
        return HAI_SE_OK
    } catch {
        setLastError(describe(error))
        return classify(error)
    }
}

private func deriveKey(
    _ shared: SharedSecret, ephPub: Data, recipientPub: Data
) -> SymmetricKey {
    return shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephPub + recipientPub,
        sharedInfo: INFO,
        outputByteCount: 32
    )
}

/// Encrypt to an enclave public key (x963). Never prompts.
@_cdecl("hai_se_encrypt")
public func hai_se_encrypt(
    _ pubPtr: UnsafePointer<UInt8>, _ pubLen: Int,
    _ ptPtr: UnsafePointer<UInt8>, _ ptLen: Int,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let pubData = Data(bytes: pubPtr, count: pubLen)
    let pt = Data(bytes: ptPtr, count: ptLen)
    do {
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: pubData)
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let shared = try eph.sharedSecretFromKeyAgreement(with: recipient)
        let key = deriveKey(shared, ephPub: ephPub, recipientPub: pubData)
        let sealed = try AES.GCM.seal(pt, using: key)
        var out = Data([VERSION])
        out.append(ephPub)
        out.append(sealed.combined!)
        writeOut(out, outPtr, outLen)
        return HAI_SE_OK
    } catch {
        setLastError(describe(error))
        return HAI_SE_BAD_INPUT
    }
}

/// Decrypt with the enclave key. Requires user presence unless the shared
/// context has already been authenticated this process.
@_cdecl("hai_se_decrypt")
public func hai_se_decrypt(
    _ handlePtr: UnsafePointer<UInt8>, _ handleLen: Int,
    _ ctPtr: UnsafePointer<UInt8>, _ ctLen: Int,
    _ reasonPtr: UnsafePointer<CChar>,
    _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>
) -> Int32 {
    let handle = Data(bytes: handlePtr, count: handleLen)
    let ct = Data(bytes: ctPtr, count: ctLen)
    let reason = String(cString: reasonPtr)
    guard ct.count > 1 + 65 + 12 + 16, ct[ct.startIndex] == VERSION else {
        setLastError("malformed ciphertext")
        return HAI_SE_BAD_INPUT
    }
    let ephPub = ct.subdata(in: (ct.startIndex + 1)..<(ct.startIndex + 66))
    let body = ct.subdata(in: (ct.startIndex + 66)..<ct.endIndex)

    let ctx = context(reason: reason)
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: handle, authenticationContext: ctx)
    } catch {
        setLastError(describe(error))
        return HAI_SE_INVALID_KEY
    }
    let shared: SharedSecret
    do {
        let eph = try P256.KeyAgreement.PublicKey(x963Representation: ephPub)
        shared = try key.sharedSecretFromKeyAgreement(with: eph)
    } catch {
        setLastError(describe(error))
        let c = classify(error)
        if c == HAI_SE_CANCELLED || c == HAI_SE_AUTH_FAILED {
            // Don't keep a context that failed to authenticate.
            hai_se_reset_auth()
        }
        return c
    }
    do {
        let k = deriveKey(
            shared, ephPub: ephPub, recipientPub: key.publicKey.x963Representation)
        let pt = try AES.GCM.open(AES.GCM.SealedBox(combined: body), using: k)
        writeOut(pt, outPtr, outLen)
        return HAI_SE_OK
    } catch {
        setLastError(describe(error))
        return HAI_SE_BAD_INPUT
    }
}