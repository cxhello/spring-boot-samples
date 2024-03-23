package top.cxhello.common.util;

import lombok.Data;

import javax.validation.constraints.NotBlank;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Data
public class KeyInfo {

    /**
     * 公钥
     */
    @NotBlank(message = "公钥不能为空")
    private String publicKeyStr;

    /**
     * 私钥
     */
    private String privateKeyStr;


}
