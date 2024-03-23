package top.cxhello.webservice.util;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.jaxws.endpoint.dynamic.JaxWsDynamicClientFactory;

/**
 * @author cxhello
 * @date 2024/3/22
 */
public class WebServiceUtils {

    public static void main(String[] args) throws Exception {
        JaxWsDynamicClientFactory dcf = JaxWsDynamicClientFactory.newInstance();
        Object[] objects;
        try (Client client = dcf.createClient("http://localhost:8084/services/helloService?wsdl")) {
            //hi方法名 后面是可变参数
            objects = client.invoke("hi", "zhangsan");
        }
        //输出调用结果
        System.out.println(objects[0].getClass());
        System.out.println(objects[0].toString());
    }

}
