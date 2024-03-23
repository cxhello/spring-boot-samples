package top.cxhello.common.util;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLEncoder;

/**
 * @author cxhello
 * @date 2024/3/22
 */
public class DownloadUtils {

    public static void download(HttpServletResponse response, String filePath) throws IOException {
        File downloadFile = new File(filePath);
        response.setHeader("Content-disposition","attachment;filename=" + URLEncoder.encode(downloadFile.getName(),"UTF-8"));
        try (FileInputStream in = new FileInputStream(downloadFile);
             ServletOutputStream out = response.getOutputStream()) {
            int len;
            byte[] buffer = new byte[1024];
            while((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        }
    }

}
