package top.cxhello.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import top.cxhello.common.util.ApiResponse;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Slf4j
@RestControllerAdvice
public class ExceptionAdvice {

    @ExceptionHandler(value = HttpRequestMethodNotSupportedException.class)
    public ApiResponse<String> validExceptionHandler(HttpRequestMethodNotSupportedException e) {
        log.error(e.getMessage(), e);
        return ApiResponse.fail(HttpStatus.METHOD_NOT_ALLOWED.value(), HttpStatus.METHOD_NOT_ALLOWED.getReasonPhrase());
    }

    @ExceptionHandler(value = HttpMessageNotReadableException.class)
    public ApiResponse<String> validExceptionHandler(HttpMessageNotReadableException e) {
        log.error(e.getMessage(), e);
        return ApiResponse.fail(HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.getReasonPhrase());
    }

    @ExceptionHandler(value = ConstraintViolationException.class)
    public ApiResponse<String> validExceptionHandler(ConstraintViolationException e) {
        ConstraintViolation<?> next = e.getConstraintViolations().iterator().next();
        return ApiResponse.fail(HttpStatus.BAD_REQUEST.value(), next.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ApiResponse<String> validExceptionHandler(MethodArgumentNotValidException e) {
        ObjectError objectError = e.getBindingResult().getAllErrors().get(0);
        return ApiResponse.fail(HttpStatus.BAD_REQUEST.value(), objectError.getDefaultMessage());
    }

    @ExceptionHandler(BindException.class)
    public ApiResponse<String> validExceptionHandler(BindException e) {
        ObjectError objectError = e.getBindingResult().getAllErrors().get(0);
        return ApiResponse.fail(HttpStatus.BAD_REQUEST.value(), objectError.getDefaultMessage());
    }

    @ExceptionHandler(value = BusinessException.class)
    //@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
    public ApiResponse<String> validExceptionHandler(BusinessException e) {
        return ApiResponse.fail(e.getMessage());
    }

    @ExceptionHandler(value = Exception.class)
    public ApiResponse<String> validExceptionHandler(Exception e) {
        log.error(e.getMessage(), e);
        return ApiResponse.fail();
    }

}
