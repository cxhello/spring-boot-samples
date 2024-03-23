package top.cxhello.webservice.config;

import org.apache.cxf.Bus;
import org.apache.cxf.jaxws.EndpointImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import top.cxhello.webservice.service.HelloService;

import javax.annotation.Resource;
import javax.xml.ws.Endpoint;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Configuration
public class HelloEndpointConfig {

    @Resource
    private Bus bus;

    @Resource
    private HelloService helloService;

    @Bean
    public Endpoint helloEndpoint(){
        EndpointImpl endpoint = new EndpointImpl(bus, helloService);
        endpoint.publish("/helloService");
        return endpoint;
    }

}
