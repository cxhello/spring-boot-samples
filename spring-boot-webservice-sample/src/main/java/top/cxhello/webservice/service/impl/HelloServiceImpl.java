package top.cxhello.webservice.service.impl;

import org.springframework.stereotype.Service;
import top.cxhello.webservice.entity.UserDto;
import top.cxhello.webservice.service.HelloService;

import javax.jws.WebService;
import javax.xml.ws.BindingType;
import java.util.List;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@WebService(
        /** 和接口的服务名称保持一致 */
        serviceName = HelloService.SERVICE_NAME,
        /** 和接口的命名空间保持一致 */
        targetNamespace = HelloService.TARGET_NAMESPACE,
        /** 接口全路径 */
        endpointInterface = "top.cxhello.webservice.service.HelloService"
)
@BindingType(value = "http://www.w3.org/2003/05/soap/bindings/HTTP/")
@Service
public class HelloServiceImpl implements HelloService {
    @Override
    public String hi(String userName) {
        return "hi " + userName;
    }

    @Override
    public List<UserDto> activeUsers(List<UserDto> userDtos) {
        for (UserDto userDto : userDtos) {
            userDto.setActive(Boolean.TRUE);
        }
        return userDtos;
    }
}
