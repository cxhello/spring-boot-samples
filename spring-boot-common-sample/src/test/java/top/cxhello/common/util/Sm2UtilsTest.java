package top.cxhello.common.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static top.cxhello.common.util.Sm2Utils.*;
import static top.cxhello.common.util.Sm2Utils.verify;

/**
 * @author cxhello
 * @date 2024/7/9
 */
class Sm2UtilsTest {

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

    @Test
    void testOpenSsl1Sign() throws FileNotFoundException {
        // test openssl 1.1.0 pkcs8 sign 标准EC公钥 OID:1.2.840.10045.2.1
        String sign = sign(TEST_DATA, loadPrivateKey(ResourceUtils.getFile("classpath:key/sm2PrivateKey_20240709110248.der").toPath()));
        X509Certificate x509Certificate = CertUtils.load(ResourceUtils.getFile("classpath:key/sm2Certificate_20240709110323.crt").getPath());
        assertTrue(verify(TEST_DATA, x509Certificate.getPublicKey(), sign));
    }

    @Test
    void testOpenSsl3Sign() throws IOException {
        // test openssl 3.x pkcs8 sign 国密标准sm2p256v1 OID:1.2.156.10197.1.301
        // TODO: 2024/7/9 由于openssl 3.x生成的私钥不支持，暂时无法测试通过
        String sign = sign(TEST_DATA, loadPrivateKey(ResourceUtils.getFile("classpath:key/sm2PrivateKey_20240709110941.der").toPath()));
        X509Certificate x509Certificate = CertUtils.load(ResourceUtils.getFile("classpath:key/sm2Certificate_20240709111011.crt").getPath());
        assertTrue(verify(TEST_DATA, x509Certificate.getPublicKey(), sign));
    }

}
