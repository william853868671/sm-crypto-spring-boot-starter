package com.github.william853868671.smcrypto.samples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 演示应用启动类。
 *
 * <p>只要 classpath 上有 sm-crypto-spring-boot-starter，Starter 的自动配置就会生效：
 * 配置好 {@code smcfb.client-public-key} 后，标了 {@code @EncryptedResponse} 的接口返回体自动加密。</p>
 */
@SpringBootApplication
public class SampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleApplication.class, args);
    }
}
