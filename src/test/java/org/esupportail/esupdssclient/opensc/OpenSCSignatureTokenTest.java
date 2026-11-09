package org.esupportail.esupdssclient.opensc;

import org.junit.Assert;
import org.junit.Test;

import java.text.MessageFormat;
import java.util.Arrays;

/**
 * JUnit test for {@link OpenSCSignatureToken#splitCommand(String)}.
 */
public class OpenSCSignatureTokenTest {

	@Test
	public void splitsOnWhitespace() {
		Assert.assertEquals(Arrays.asList("opensc-tool", "-i"), OpenSCSignatureToken.splitCommand("opensc-tool  -i "));
	}

	@Test
	public void stripsQuotesAroundId() {
		String command = MessageFormat.format("pkcs11-tool -r --id ''{0}'' --type cert", "0001");
		Assert.assertEquals(Arrays.asList("pkcs11-tool", "-r", "--id", "0001", "--type", "cert"), OpenSCSignatureToken.splitCommand(command));
	}

	@Test
	public void keepsQuotedPathsWithSpacesAndPinCharactersIntact() {
		String command = MessageFormat.format(
				"pkcs11-tool --sign -v --id ''{0}'' -p {1} --mechanism SHA256-RSA-PKCS --input-file \"{2}\" --output-file \"{3}\"",
				"0001", "1&2^3%", "C:\\Users\\Jan Novák\\AppData\\Local\\Temp\\x\\toSign", "C:\\Users\\Jan Novák\\AppData\\Local\\Temp\\x\\signed");
		Assert.assertEquals(Arrays.asList("pkcs11-tool", "--sign", "-v", "--id", "0001", "-p", "1&2^3%", "--mechanism", "SHA256-RSA-PKCS",
				"--input-file", "C:\\Users\\Jan Novák\\AppData\\Local\\Temp\\x\\toSign",
				"--output-file", "C:\\Users\\Jan Novák\\AppData\\Local\\Temp\\x\\signed"), OpenSCSignatureToken.splitCommand(command));
	}

	@Test
	public void keepsQuotedModulePath() {
		Assert.assertEquals(Arrays.asList("pkcs11-tool", "-L", "--module", "C:\\Program Files\\Vendor\\p11.dll"),
				OpenSCSignatureToken.splitCommand("pkcs11-tool -L --module \"C:\\Program Files\\Vendor\\p11.dll\""));
	}
}
