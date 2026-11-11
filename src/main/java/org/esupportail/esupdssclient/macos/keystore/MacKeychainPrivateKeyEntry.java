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

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

/**
 * A macOS identity, identified by its certificate. The private key stays with macOS (or on the
 * card) and is looked up again by certificate when signing.
 */
public class MacKeychainPrivateKeyEntry implements DSSPrivateKeyEntry {

	private final CertificateToken certificate;

	private final byte[] encoded;

	MacKeychainPrivateKeyEntry(final CertificateToken certificate, final byte[] encoded) {
		this.certificate = certificate;
		this.encoded = encoded;
	}

	byte[] getEncoded() {
		return encoded;
	}

	@Override
	public CertificateToken getCertificate() {
		return certificate;
	}

	@Override
	public CertificateToken[] getCertificateChain() {
		return new CertificateToken[] { certificate };
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return EncryptionAlgorithm.forKey(certificate.getPublicKey());
	}
}
