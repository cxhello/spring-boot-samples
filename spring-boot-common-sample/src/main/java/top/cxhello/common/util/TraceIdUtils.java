package top.cxhello.common.util;

import org.slf4j.MDC;

/**
 * @author cxhello
 * @date 2024/3/22
 */
public class TraceIdUtils {

    private static final String TRACE_ID = "traceId";

    public static String getTraceId() {
        return MDC.get(TRACE_ID);
    }

}
