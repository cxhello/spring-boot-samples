package top.cxhello.common.util;

import cn.hutool.crypto.KeyUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.SM2;
import top.cxhello.common.exception.CertException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author cxhello
 * @date 2024/7/9
 */
public class Sm2Utils {

    private static final String ALGORITHM = "SM2";

    public static final String SIGNATURE_ALGORITHM = "SM3withSM2";

    private Sm2Utils() {

    }

    /**
     * 生成公钥&私钥
     * @return
     */
    public static KeyInfo generate() {
        KeyPair keyPair = SecureUtil.generateKeyPair(ALGORITHM);
        // 获取公钥和私钥
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.setPublicKeyStr(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        keyInfo.setPrivateKeyStr(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        return keyInfo;
    }

    /**
     * 加载公钥-通过文件路径
     * @param path
     * @return
     */
    public static PublicKey loadPublicKey(Path path) {
        try {
            // 读取文件内容
            byte[] keyBytes = Files.readAllBytes(path);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyUtil.generatePublicKey(ALGORITHM, spec);
        } catch (IOException e) {
            throw new CertException(e);
        }
    }

    /**
     * 加载公钥-通过字符串
     * @param publicKeyStr
     * @return
     */
    public static PublicKey loadPublicKeyStr(String publicKeyStr) {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyUtil.generatePublicKey(ALGORITHM, spec);
    }

    /**
     * 加载私钥-通过文件路径
     * @param path
     * @return
     */
    public static PrivateKey loadPrivateKey(Path path) {
        try {
            byte[] keyBytes = Files.readAllBytes(path);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyUtil.generatePrivateKey(ALGORITHM, spec);
        } catch (IOException e) {
            throw new CertException(e);
        }
    }

    /**
     * 加载私钥-通过字符串
     * @param privateKeyStr
     * @return
     */
    public static PrivateKey loadPrivateKeyStr(String privateKeyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return KeyUtil.generatePrivateKey(ALGORITHM, keySpec);
    }

    /**
     * 使用公钥加密数据并返回Base64编码的字符串
     * @param data
     * @param publicKey
     * @return
     */
    public static String encryptString(String data, PublicKey publicKey) {
        SM2 sm2 = SmUtil.sm2(null, publicKey);
        return Base64.getEncoder().encodeToString(sm2.encrypt(data.getBytes()));
    }

    /**
     * 使用私钥解密Base64编码的加密字符串
     * @param encryptedData
     * @param privateKey
     * @return
     */
    public static String decryptString(String encryptedData, PrivateKey privateKey) {
        SM2 sm2 = SmUtil.sm2(privateKey, null);
        byte[] decryptedBytes = sm2.decrypt(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes);
    }

    /**
     * 使用私钥签名数据并返回Base64编码的字符串
     * @param data
     * @param privateKey
     * @return
     */
    public static String sign(String data, PrivateKey privateKey) {
        SM2 sm2 = SmUtil.sm2(privateKey, null);
        byte[] sign = sm2.sign(data.getBytes());
        return Base64.getEncoder().encodeToString(sign);
    }

    /**
     * 使用公钥验签
     * @param data
     * @param publicKey
     * @param sign
     * @return
     */
    public static boolean verify(String data, PublicKey publicKey, String sign) {
        SM2 sm2 = SmUtil.sm2(null, publicKey);
        return sm2.verify(data.getBytes(), Base64.getDecoder().decode(sign));
    }

}
