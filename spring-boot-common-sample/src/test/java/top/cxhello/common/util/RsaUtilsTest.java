package top.cxhello.common.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static top.cxhello.common.util.RsaUtils.*;

/**
 * @author cxhello
 * @date 2024/7/9
 */
class RsaUtilsTest {

    private static final String TEST_DATA = "data";

    @Test
    void testEncrypt() {
        KeyInfo keyInfo = generate();
        String encryptString = encryptString(TEST_DATA, loadPublicKeyStr(keyInfo.getPublicKeyStr()));
        String decryptString = decryptString(encryptString, loadPrivateKeyStr(keyInfo.getPrivateKeyStr()));
        assertEquals(TEST_DATA, decryptString);
    }

    @Test
    void testSign(@TempDir Path tempDir) {
        String name = "test";
        KeyInfo keyInfo = generate();
        CertPathInfo certPathInfo = CertUtils.generate(tempDir.toString() + "/", name, name,
                BigInteger.valueOf(System.currentTimeMillis()),
                loadPublicKeyStr(keyInfo.getPublicKeyStr()), loadPrivateKeyStr(keyInfo.getPrivateKeyStr()), SIGNATURE_ALGORITHM);
        String sign = sign(TEST_DATA, loadPrivateKey(Paths.get(certPathInfo.getPrivateKeyPath())));
        X509Certificate x509Certificate = CertUtils.load(certPathInfo.getCertPath());
        assertTrue(verify(TEST_DATA, x509Certificate.getPublicKey(), sign));
    }

}
