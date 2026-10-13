package com.github.william853868671.smcrypto;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 把纯 Java 自测套件接入 Maven 的标准测试生命周期（{@code mvn test} 即可运行）。
 */
class SmCryptoLibraryTest {

    @Test
    void backendCryptoChainSelfTestPasses() throws Exception {
        Path outDir = Path.of("target", "selftest");
        boolean ok = SecurePayloadSelfTest.run(outDir);
        assertTrue(ok, "后端国密链路自测未全部通过，详见上方控制台输出");
    }
}
