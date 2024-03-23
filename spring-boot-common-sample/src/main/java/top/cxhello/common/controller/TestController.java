package top.cxhello.common.controller;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import top.cxhello.common.exception.BusinessException;
import top.cxhello.common.util.ApiResponse;
import top.cxhello.common.util.DownloadUtils;
import top.cxhello.common.util.KeyInfo;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.io.IOException;
import java.util.Date;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Validated
@RestController
public class TestController {

    @GetMapping("/test1")
    public ApiResponse<String> test1() {
        return ApiResponse.ok();
    }

    @GetMapping("/test2")
    public ApiResponse<KeyInfo> test2() {
        return ApiResponse.data(new KeyInfo());
    }

    @GetMapping("/test3")
    public ApiResponse<Date> test3() {
        return ApiResponse.data(new Date());
    }

    @GetMapping("/test4")
    public ApiResponse<String> test4(@NotBlank(message = "名字不能为空") String name) {
        return ApiResponse.data(name);
    }

    @PostMapping("/test5")
    public ApiResponse<KeyInfo> test5(@Valid KeyInfo keyInfo) {
        return ApiResponse.data(keyInfo);
    }

    @PostMapping("/test6")
    public ApiResponse<KeyInfo> test6(@RequestBody @Valid KeyInfo keyInfo) {
        return ApiResponse.data(keyInfo);
    }

    @GetMapping("/test7")
    public void test7(HttpServletResponse response) throws IOException {
        DownloadUtils.download(response, "/Users/cxhello/Downloads/config");
    }

    @GetMapping("/test8")
    public ApiResponse<KeyInfo> test8() {
        if (true) {
            throw new BusinessException("业务异常");
        }
        return ApiResponse.data(new KeyInfo());
    }

    @GetMapping("/test9")
    public ApiResponse<KeyInfo> test9() {
        if (true) {
            throw new RuntimeException("运行异常");
        }
        return ApiResponse.data(new KeyInfo());
    }

}
