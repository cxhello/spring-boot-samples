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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * @author cxhello
 * @date 2024/3/22
 */
public class CertUtils {

    public static final String PUBLIC_KEY_PATH = "public_key.pem";

    public static final String PRIVATE_KEY_PATH = "private_key.der";

    public static final String CERT_PATH = ".crt";

    private CertUtils() {

    }

    /**
     * 生成证书
     * @param filePath
     * @param name
     * @param fileName
     * @param serialNumber
     * @param publicKey
     * @param privateKey
     * @param signatureAlgorithm
     * @return
     */
    public static CertPathInfo generate(String filePath, String name, String fileName, BigInteger serialNumber, PublicKey publicKey, PrivateKey privateKey, String signatureAlgorithm) {
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
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(new BouncyCastleProvider()).build(privateKey);
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
     * 加载证书
     * @param fileName
     * @return
     */
    public static X509Certificate load(String fileName) {
        X509Certificate cert;
        try (FileInputStream fis = new FileInputStream(fileName)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
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
            CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
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
