package top.cxhello.common.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Resource
    private LogTraceIdInterceptor logTraceIdInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(logTraceIdInterceptor);
    }

}
