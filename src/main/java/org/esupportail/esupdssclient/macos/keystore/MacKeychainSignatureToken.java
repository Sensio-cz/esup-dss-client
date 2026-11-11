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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.esupportail.esupdssclient.CancelledOperationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Signs with the identities macOS offers: keychain certificates and smart cards or tokens, like
 * {@code MSCAPISignatureToken} does with the Windows certificate store. See {@link MacSecurity}.
 */
public class MacKeychainSignatureToken implements SignatureTokenConnection {

	private static final Logger logger = LoggerFactory.getLogger(MacKeychainSignatureToken.class);

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		final List<DSSPrivateKeyEntry> keys = new ArrayList<>();
		for (final byte[] der : MacSecurity.identityCertificates()) {
			try {
				final CertificateToken certificate = DSSUtils.loadCertificate(der);
				keys.add(new MacKeychainPrivateKeyEntry(certificate, der));
				logger.info("macOS identity: {}", certificate.getSubject().getPrettyPrintRFC2253());
			} catch (RuntimeException e) {
				logger.warn("Skipping a macOS identity whose certificate cannot be read: {}", e.getMessage());
			}
		}
		return keys;
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
		return sign(toBeSigned, signatureAlgorithm(keyEntry, digestAlgorithm), keyEntry);
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, SignatureAlgorithm signatureAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
		return signWith(signatureAlgorithm, "Message", toBeSigned.getBytes(), keyEntry);
	}

	@Override
	public SignatureValue signDigest(Digest digest, DSSPrivateKeyEntry keyEntry) throws DSSException {
		return signDigest(digest, signatureAlgorithm(keyEntry, digest.getAlgorithm()), keyEntry);
	}

	@Override
	public SignatureValue signDigest(Digest digest, SignatureAlgorithm signatureAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {
		if (signatureAlgorithm.getDigestAlgorithm() != digest.getAlgorithm()) {
			throw new IllegalArgumentException("Digest " + digest.getAlgorithm() + " does not match " + signatureAlgorithm);
		}
		return signWith(signatureAlgorithm, "Digest", digest.getValue(), keyEntry);
	}

	private SignatureValue signWith(SignatureAlgorithm signatureAlgorithm, String input, byte[] data, DSSPrivateKeyEntry keyEntry) {
		if (!(keyEntry instanceof MacKeychainPrivateKeyEntry)) {
			throw new IllegalArgumentException("Not a macOS keychain key: " + keyEntry);
		}
		final String algorithm = secKeyAlgorithm(signatureAlgorithm, input);
		logger.info("Signing with {} ({})", keyEntry.getCertificate().getSubject().getPrettyPrintRFC2253(), algorithm);
		try {
			final SignatureValue value = new SignatureValue();
			value.setAlgorithm(signatureAlgorithm);
			value.setValue(MacSecurity.sign(((MacKeychainPrivateKeyEntry) keyEntry).getEncoded(), algorithm, data));
			return value;
		} catch (MacSecurity.CancelledException e) {
			throw new CancelledOperationException(e.getMessage(), e);
		} catch (RuntimeException e) {
			throw new DSSException("Unable to sign: " + e.getMessage(), e);
		}
	}

	private static SignatureAlgorithm signatureAlgorithm(DSSPrivateKeyEntry keyEntry, DigestAlgorithm digestAlgorithm) {
		final SignatureAlgorithm algorithm = SignatureAlgorithm.getAlgorithm(keyEntry.getEncryptionAlgorithm(), digestAlgorithm);
		if (algorithm == null) {
			throw new UnsupportedOperationException("No signature algorithm for " + keyEntry.getEncryptionAlgorithm() + " with " + digestAlgorithm);
		}
		return algorithm;
	}

	/** Name of the {@code kSecKeyAlgorithm...} constant for a signature over a message or a digest. */
	static String secKeyAlgorithm(SignatureAlgorithm signatureAlgorithm, String input) {
		final DigestAlgorithm digest = signatureAlgorithm.getDigestAlgorithm();
		if (digest == null) {
			throw new UnsupportedOperationException("Unsupported signature algorithm " + signatureAlgorithm);
		}
		final String hash;
		switch (digest) {
			case SHA1: hash = "SHA1"; break;
			case SHA224: hash = "SHA224"; break;
			case SHA256: hash = "SHA256"; break;
			case SHA384: hash = "SHA384"; break;
			case SHA512: hash = "SHA512"; break;
			default: throw new UnsupportedOperationException("macOS cannot sign with " + digest);
		}
		final EncryptionAlgorithm encryption = signatureAlgorithm.getEncryptionAlgorithm();
		if (EncryptionAlgorithm.RSA == encryption) {
			return "kSecKeyAlgorithmRSASignature" + input + "PKCS1v15" + hash;
		}
		if (EncryptionAlgorithm.RSASSA_PSS == encryption) {
			return "kSecKeyAlgorithmRSASignature" + input + "PSS" + hash;
		}
		if (EncryptionAlgorithm.ECDSA == encryption) {
			return "kSecKeyAlgorithmECDSASignature" + input + "X962" + hash;
		}
		throw new UnsupportedOperationException("macOS cannot sign with " + encryption);
	}

	@Override
	public void close() {
		// Nothing held: every call asks macOS afresh.
	}
}
