/**
 * Concédée sous licence EUPL, version 1.1 ou – dès leur approbation par la Commission européenne - versions ultérieures de l’EUPL (la «Licence»).
 * Vous ne pouvez utiliser la présente œuvre que conformément à la Licence.
 * Vous pouvez obtenir une copie de la Licence à l’adresse suivante:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Sauf obligation légale ou contractuelle écrite, le logiciel distribué sous la Licence est distribué «en l’état»,
 * SANS GARANTIES OU CONDITIONS QUELLES QU’ELLES SOIENT, expresses ou implicites.
 * Consultez la Licence pour les autorisations et les restrictions linguistiques spécifiques relevant de la Licence.
 */
package org.esupportail.esupdssclient.macos.keystore;

import com.sun.jna.Memory;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Signing identities from the macOS Security framework, through JNA.
 *
 * <p>This is the macOS counterpart of Windows CAPI: identities come from the keychains and from
 * every smart card or token whose middleware installed a CryptoTokenKit extension (I.CA
 * SecureStore, OpenSC, Apple's PIV driver...). Signing goes through the system, so the PIN is
 * asked by the token's own dialog. Java's KeychainStore cannot do this: it never sees tokens.
 */
final class MacSecurity {

	/** Thrown when the user dismissed the PIN or keychain dialog. */
	static final class CancelledException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		CancelledException(final String message) {
			super(message);
		}
	}

	private static final int ERR_SEC_SUCCESS = 0;
	private static final int ERR_SEC_ITEM_NOT_FOUND = -25300;
	private static final long ERR_SEC_USER_CANCELED = -128;
	private static final int CF_STRING_ENCODING_UTF8 = 0x08000100;

	private static final NativeLibrary CF = NativeLibrary.getInstance("CoreFoundation");
	private static final NativeLibrary SEC = NativeLibrary.getInstance("Security");

	private MacSecurity() {
	}

	/** DER-encoded certificates of all signing identities currently available. */
	static List<byte[]> identityCertificates() {
		final List<byte[]> certificates = new ArrayList<>();
		forEachIdentity(identity -> {
			final byte[] der = certificate(identity);
			if (der != null && certificates.stream().noneMatch(c -> Arrays.equals(c, der))) {
				certificates.add(der);
			}
			return false;
		});
		return certificates;
	}

	/**
	 * Signs with the private key of the identity whose certificate is {@code certificate}.
	 *
	 * @param algorithm name of a {@code kSecKeyAlgorithm...} constant
	 */
	static byte[] sign(final byte[] certificate, final String algorithm, final byte[] data) {
		final byte[][] result = new byte[1][];
		final boolean found = forEachIdentity(identity -> {
			if (!Arrays.equals(certificate, certificate(identity))) {
				return false;
			}
			result[0] = signWith(identity, algorithm, data);
			return true;
		});
		if (!found) {
			throw new IllegalStateException("The certificate is no longer available (card removed?)");
		}
		return result[0];
	}

	private interface IdentityVisitor {
		/** @return true to stop */
		boolean visit(Pointer identity);
	}

	private static boolean forEachIdentity(final IdentityVisitor visitor) {
		final Pointer query = call(CF, "CFDictionaryCreateMutable", Pointer.class, null, 0L,
				CF.getGlobalVariableAddress("kCFTypeDictionaryKeyCallBacks"),
				CF.getGlobalVariableAddress("kCFTypeDictionaryValueCallBacks"));
		try {
			put(query, constant(SEC, "kSecClass"), constant(SEC, "kSecClassIdentity"));
			put(query, constant(SEC, "kSecMatchLimit"), constant(SEC, "kSecMatchLimitAll"));
			put(query, constant(SEC, "kSecReturnRef"), constant(CF, "kCFBooleanTrue"));
			final PointerByReference out = new PointerByReference();
			final int status = call(SEC, "SecItemCopyMatching", Integer.class, query, out);
			if (status == ERR_SEC_ITEM_NOT_FOUND) {
				return false;
			}
			if (status != ERR_SEC_SUCCESS) {
				throw new IllegalStateException("SecItemCopyMatching failed: " + status);
			}
			final Pointer identities = out.getValue();
			try {
				final long count = call(CF, "CFArrayGetCount", Long.class, identities);
				for (long i = 0; i < count; i++) {
					if (visitor.visit(call(CF, "CFArrayGetValueAtIndex", Pointer.class, identities, i))) {
						return true;
					}
				}
				return false;
			} finally {
				release(identities);
			}
		} finally {
			release(query);
		}
	}

	private static byte[] certificate(final Pointer identity) {
		final PointerByReference cert = new PointerByReference();
		if (call(SEC, "SecIdentityCopyCertificate", Integer.class, identity, cert) != ERR_SEC_SUCCESS) {
			return null;
		}
		try {
			final Pointer data = call(SEC, "SecCertificateCopyData", Pointer.class, cert.getValue());
			try {
				return bytes(data);
			} finally {
				release(data);
			}
		} finally {
			release(cert.getValue());
		}
	}

	private static byte[] signWith(final Pointer identity, final String algorithm, final byte[] data) {
		final PointerByReference key = new PointerByReference();
		final int status = call(SEC, "SecIdentityCopyPrivateKey", Integer.class, identity, key);
		if (status != ERR_SEC_SUCCESS) {
			throw new IllegalStateException("SecIdentityCopyPrivateKey failed: " + status);
		}
		final Pointer input = call(CF, "CFDataCreate", Pointer.class, null, data, (long) data.length);
		try {
			final PointerByReference error = new PointerByReference();
			final Pointer signature = call(SEC, "SecKeyCreateSignature", Pointer.class,
					key.getValue(), constant(SEC, algorithm), input, error);
			if (signature == null) {
				throw signatureError(error.getValue());
			}
			try {
				return bytes(signature);
			} finally {
				release(signature);
			}
		} finally {
			release(input);
			release(key.getValue());
		}
	}

	private static RuntimeException signatureError(final Pointer error) {
		if (error == null) {
			return new IllegalStateException("SecKeyCreateSignature failed");
		}
		try {
			final long code = call(CF, "CFErrorGetCode", Long.class, error);
			final Pointer description = call(CF, "CFErrorCopyDescription", Pointer.class, error);
			final String message;
			try {
				message = string(description);
			} finally {
				release(description);
			}
			if (code == ERR_SEC_USER_CANCELED) {
				return new CancelledException(message);
			}
			return new IllegalStateException("SecKeyCreateSignature failed (" + code + "): " + message);
		} finally {
			release(error);
		}
	}

	private static Pointer constant(final NativeLibrary library, final String name) {
		return library.getGlobalVariableAddress(name).getPointer(0);
	}

	private static void put(final Pointer dictionary, final Pointer key, final Pointer value) {
		CF.getFunction("CFDictionarySetValue").invokeVoid(new Object[] { dictionary, key, value });
	}

	private static byte[] bytes(final Pointer data) {
		if (data == null) {
			return null;
		}
		final long length = call(CF, "CFDataGetLength", Long.class, data);
		return call(CF, "CFDataGetBytePtr", Pointer.class, data).getByteArray(0, (int) length);
	}

	private static String string(final Pointer cfString) {
		if (cfString == null) {
			return "";
		}
		final Memory buffer = new Memory(1024);
		final byte ok = call(CF, "CFStringGetCString", Byte.class, cfString, buffer, 1024L, CF_STRING_ENCODING_UTF8);
		return ok != 0 ? new String(buffer.getByteArray(0, (int) buffer.indexOf(0, (byte) 0)), StandardCharsets.UTF_8) : "";
	}

	private static void release(final Pointer cf) {
		if (cf != null) {
			CF.getFunction("CFRelease").invokeVoid(new Object[] { cf });
		}
	}

	private static <T> T call(final NativeLibrary library, final String function, final Class<T> returnType, final Object... args) {
		return returnType.cast(library.getFunction(function).invoke(returnType, args));
	}
}
