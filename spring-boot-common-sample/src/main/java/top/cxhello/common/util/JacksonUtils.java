package top.cxhello.common.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author cxhello
 * @date 2024/3/22
 */
public class JacksonUtils {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static String toJSONString(Object object) throws JsonProcessingException {
        return MAPPER.writeValueAsString(object);
    }

}
