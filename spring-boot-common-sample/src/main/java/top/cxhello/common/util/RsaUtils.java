package top.cxhello.common.util;

import top.cxhello.common.exception.CertException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author cxhello
 * @date 2024/7/9
 */
public class RsaUtils {

    private static final String ALGORITHM = "RSA";

    private static final Integer RSA_LENGTH = 2048;

    private static final String ALGORITHM_SECURE_MODE_PADDING_SCHEME = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private RsaUtils() {

    }

    /**
     * 生成公钥&私钥
     * @return
     */
    public static KeyInfo generate() {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        }
        keyPairGenerator.initialize(RSA_LENGTH, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
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
            // 使用KeyFactory将其转换为PublicKey对象
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CertException(e);
        }
    }

    /**
     * 加载公钥-通过字符串
     * @param publicKeyStr
     * @return
     */
    public static PublicKey loadPublicKeyStr(String publicKeyStr) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
            // 使用KeyFactory将其转换为PublicKey对象
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CertException(e);
        }
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
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CertException(e);
        }
    }

    /**
     * 加载私钥-通过字符串
     * @param privateKeyStr
     * @return
     */
    public static PrivateKey loadPrivateKeyStr(String privateKeyStr) {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CertException(e);
        }
    }

    /**
     * 使用公钥加密数据并返回Base64编码的字符串
     * @param data
     * @param publicKey
     * @return
     */
    public static String encryptString(String data, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_SECURE_MODE_PADDING_SCHEME);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new CertException(e);
        }
    }

    /**
     * 使用私钥解密Base64编码的加密字符串
     * @param encryptedData
     * @param privateKey
     * @return
     */
    public static String decryptString(String encryptedData, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_SECURE_MODE_PADDING_SCHEME);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new CertException(e);
        }
    }

    /**
     * 使用私钥签名数据并返回Base64编码的字符串
     * @param data
     * @param privateKey
     * @return
     */
    public static String sign(String data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data.getBytes());
            byte[] sign = signature.sign();
            return Base64.getEncoder().encodeToString(sign);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CertException(e);
        }
    }

    /**
     * 使用公钥验签
     * @param data
     * @param publicKey
     * @param sign
     * @return
     */
    public static boolean verify(String data, PublicKey publicKey, String sign) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(data.getBytes());
            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CertException(e);
        }
    }

}
