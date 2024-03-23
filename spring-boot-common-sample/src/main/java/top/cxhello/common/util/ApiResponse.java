package top.cxhello.common.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import org.springframework.http.HttpStatus;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Data
public class ApiResponse<T> {

    private Integer code; // HTTP状态码
    private String message; // 返回消息
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String traceId;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private T data; // 返回的数据

    public static ApiResponse<String> ok() {
        return new ApiResponse<>(HttpStatus.OK.value(), HttpStatus.OK.getReasonPhrase());
    }

    public static <T> ApiResponse<T> data(T data) {
        return new ApiResponse<>(HttpStatus.OK.value(), HttpStatus.OK.getReasonPhrase(), data);
    }

    public static ApiResponse<String> fail() {
        return new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
    }

    public static ApiResponse<String> fail(String message) {
        return new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(), message);
    }

    public static ApiResponse<String> fail(Integer code, String message) {
        return new ApiResponse<>(code, message);
    }

    public ApiResponse(Integer code, String message) {
        this.code = code;
        this.message = message;
        this.traceId = TraceIdUtils.getTraceId();
    }

    public ApiResponse(Integer code, String message, T data) {
        this.code = code;
        this.message = message;
        this.traceId = TraceIdUtils.getTraceId();
        this.data = data;
    }

}
