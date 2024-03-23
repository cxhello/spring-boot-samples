package top.cxhello.common.util;

import lombok.Data;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Data
public class CertPathInfo {

    /**
     * 公钥地址
     */
    private String publicKeyPath;

    /**
     * 私钥地址
     */
    private String privateKeyPath;

    /**
     * 证书地址
     */
    private String certPath;

}
