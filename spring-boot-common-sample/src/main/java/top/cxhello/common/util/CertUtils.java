package top.cxhello.common.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.web.multipart.MultipartFile;
import top.cxhello.common.exception.CertException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;

/**
 * @author cxhello
 * @date 2024/3/22
 */
public class CertUtils {

    private static final String ALGORITHM = "RSA";

    private static final Integer RSA_LENGTH = 2048;

    private static final String SIGN_ALGORITHM = "SHA256WITHRSA";

    private static final String ALGORITHM_SECURE_MODE_PADDING_SCHEME = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";

    public static final String PUBLIC_KEY_PATH = "public_key.pem";

    public static final String PRIVATE_KEY_PATH = "private_key.der";

    public static final String CERT_PATH = ".crt";

    private CertUtils() {

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
     * 生成证书
     * @param filePath
     * @param name
     * @param fileName
     * @param serialNumber
     * @param publicKey
     * @param privateKey
     * @return
     */
    public static CertPathInfo generate(String filePath, String name, String fileName, BigInteger serialNumber, PublicKey publicKey, PrivateKey privateKey) {
        X500Name x500Name = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, name)
                //.addRDN(BCStyle.OU, "cxhello")
                .addRDN(BCStyle.O, "cxhello Ltd.")
                .addRDN(BCStyle.L, "Beijing")
                .addRDN(BCStyle.ST, "Beijing")
                .addRDN(BCStyle.C, "CN")
                .build();
        X500Principal dnName = null;
        try {
            // 使用X.509标准
            dnName = new X500Principal(x500Name.getEncoded());
        } catch (IOException e) {
            throw new CertException(e);
        }
        // 证书的有效期限
        Date notBefore = new Date(System.currentTimeMillis());
        // Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000); // 有效期1年
        Date notAfter = parseDate("2099-12-31 23:59:59");

        // 使用Java的证书生成类
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, serialNumber, notBefore, notAfter, dnName, publicKey);
        CertPathInfo certPathInfo = new CertPathInfo();
        certPathInfo.setPublicKeyPath(filePath + PUBLIC_KEY_PATH);
        certPathInfo.setPrivateKeyPath(filePath + PRIVATE_KEY_PATH);
        certPathInfo.setCertPath(filePath + fileName + CERT_PATH);
        try {
            // 签名算法
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGN_ALGORITHM).build(privateKey);
            // 生成证书
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certHolder);
            // 保存证书
            saveToFile(certPathInfo.getPublicKeyPath(), publicKey.getEncoded());
            saveToFile(certPathInfo.getPrivateKeyPath(), privateKey.getEncoded());
            saveToFile(certPathInfo.getCertPath(), certificate.getEncoded());
        } catch (OperatorCreationException | CertificateException | IOException e) {
            throw new CertException(e);
        }
        return certPathInfo;
    }

    /**
     * 加载公钥
     * @param filename
     * @return
     */
    public static PublicKey loadPublicKey(String filename) {
        try {
            // 读取文件内容
            byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
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
     * @param filename
     * @return
     */
    public static PrivateKey loadPrivateKey(String filename) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
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
     * 加载证书
     * @param filename
     * @return
     */
    public static X509Certificate load(String filename) {
        X509Certificate cert;
        try (FileInputStream fis = new FileInputStream(filename)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // 加载证书文件
            cert = (X509Certificate) cf.generateCertificate(fis);
            cert.checkValidity();
        } catch (IOException | CertificateException e) {
            throw new CertException(e);
        }
        return cert;
    }

    /**
     * 加载证书
     * @param file
     * @return
     */
    public static X509Certificate load(MultipartFile file) {
        X509Certificate cert;
        try (InputStream is = file.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            // 通过MultipartFile获取输入流来加载证书文件
            cert = (X509Certificate) cf.generateCertificate(is);
            cert.checkValidity();
        } catch (IOException | CertificateException e) {
            throw new CertException(e);
        }
        return cert;
    }

    /**
     * 获取证书通用名称
     * @param x509Certificate
     * @return
     */
    public static String getCommonName(X509Certificate x509Certificate) {
        LdapName ln = null;
        try {
            ln = new LdapName(x509Certificate.getSubjectX500Principal().getName());
        } catch (InvalidNameException e) {
            throw new CertException(e);
        }
        String commonName = null;
        for (Rdn rdn : ln.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("CN")) {
                commonName = rdn.getValue().toString();
                break;
            }
        }
        return commonName;
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
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
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
            Signature signature = Signature.getInstance(SIGN_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(data.getBytes());
            return signature.verify(Base64.getDecoder().decode(sign));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CertException(e);
        }
    }

    /**
     * 保存文件
     * @param fileName
     * @param bytes
     * @throws IOException
     */
    private static void saveToFile(String fileName, byte[] bytes) throws IOException {
        Path path = Paths.get(fileName).getParent();
        // 检查父目录是否存在，如果不存在则创建
        if (path != null && !Files.exists(path)) {
            Files.createDirectories(path);
        }
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(bytes);
        }
    }

    public static Date parseDate(String dateStr) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime localDateTime = LocalDateTime.parse(dateStr, formatter);
        // Assuming you want the date in the system's default time zone
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

}
