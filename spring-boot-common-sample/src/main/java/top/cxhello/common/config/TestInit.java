package top.cxhello.common.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * @author cxhello
 * @date 2024/3/22
 */
@Slf4j
@Component
public class TestInit implements CommandLineRunner {

    @Override
    public void run(String... args) throws Exception {
        log.info("init finished.");
    }

}
