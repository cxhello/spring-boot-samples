package top.cxhello.common.entity;

/**
 * @author cxhello
 * @date 2024/3/22
 */
//@Data
public class Client {

    /**
     * 客户端ID
     */
    private Long clientId;

    public Long getClientId() {
        System.out.println("test" + clientId);
        return clientId;
    }

    public void setClientId(Long clientId) {
        this.clientId = clientId;
    }

}
