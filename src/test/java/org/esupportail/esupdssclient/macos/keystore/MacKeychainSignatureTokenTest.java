package org.esupportail.esupdssclient.macos.keystore;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.junit.Assert;
import org.junit.Test;

public class MacKeychainSignatureTokenTest {

	@Test
	public void mapsSignatureAlgorithmsToSecKeyAlgorithms() {
		Assert.assertEquals("kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256",
				MacKeychainSignatureToken.secKeyAlgorithm(SignatureAlgorithm.RSA_SHA256, "Message"));
		Assert.assertEquals("kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512",
				MacKeychainSignatureToken.secKeyAlgorithm(SignatureAlgorithm.RSA_SHA512, "Digest"));
		Assert.assertEquals("kSecKeyAlgorithmRSASignatureMessagePSSSHA256",
				MacKeychainSignatureToken.secKeyAlgorithm(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, "Message"));
		Assert.assertEquals("kSecKeyAlgorithmECDSASignatureMessageX962SHA384",
				MacKeychainSignatureToken.secKeyAlgorithm(SignatureAlgorithm.ECDSA_SHA384, "Message"));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void rejectsDigestsMacOsCannotSignWith() {
		MacKeychainSignatureToken.secKeyAlgorithm(SignatureAlgorithm.RSA_SHA3_256, "Message");
	}
}
