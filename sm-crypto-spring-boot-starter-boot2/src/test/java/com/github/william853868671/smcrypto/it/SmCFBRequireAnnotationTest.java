package com.github.william853868671.smcrypto.it;

import com.github.william853868671.smcrypto.crypto.Sm2KeyPair;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import com.github.william853868671.smcrypto.spring.SecureResponseAdvice;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 验证 {@code smcfb.require-annotation=true} 模式：只有显式标注 {@link com.github.william853868671.smcrypto.spring.SmCFBEncrypt}
 * / {@link com.github.william853868671.smcrypto.spring.SmCFBEncrypt} 的接口才加密，
 * 没标的接口一律明文返回（与默认的「默认即加密」相反）。复用 {@link AdviceTestController}。
 */
@SpringBootTest(classes = SmCFBRequireAnnotationTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "smcfb.enabled=true",
        "smcfb.client-public-key=${sm.test.publicKey}",
        "smcfb.server-private-key=${sm.test.serverPrivateKey}",
        "smcfb.request-decrypt-enabled=true",
        "smcfb.require-annotation=true"
})
class SmCFBRequireAnnotationTest {

    static Sm2KeyPair frontendKp;
    static Sm2KeyPair backendKp;
    static {
        frontendKp = SmCryptoUtil.generateSm2KeyPair();
        backendKp = SmCryptoUtil.generateSm2KeyPair();
        System.setProperty("sm.test.publicKey", frontendKp.getPublicKey());
        System.setProperty("sm.test.serverPrivateKey", backendKp.getPrivateKey());
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void annotated_encryptsEvenInOptInMode() throws Exception {
        // @SmCFBEncrypt 标注的接口：即便 require-annotation=true 也加密
        MvcResult result = mockMvc.perform(get("/t/enc"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(SecureResponseAdvice.HEADER_ENCRYPTED))
                .isEqualTo("true");
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(node.get("code").asInt()).isEqualTo(200);
        assertThat(node.get("data").asText()).isNotEqualTo("{\"k\":\"v\"}");
    }

    @Test
    void noAnnotation_plaintextInOptInMode() throws Exception {
        // 没标注解：require-annotation=true 下明文返回（与默认模式相反）
        MvcResult result = mockMvc.perform(get("/t/plain"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(SecureResponseAdvice.HEADER_ENCRYPTED)).isNull();
        assertThat(result.getResponse().getContentAsString()).contains("\"k\":\"v\"");
    }

    @Test
    void explicitFalse_stillPlaintextInOptInMode() throws Exception {
        // @SmCFBEncrypt(false)：显式关闭，明文返回
        MvcResult result = mockMvc.perform(get("/t/disabled"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(SecureResponseAdvice.HEADER_ENCRYPTED)).isNull();
        assertThat(result.getResponse().getContentAsString()).contains("\"k\":\"v\"");
    }

    /** 测试用的 Spring Boot 配置类（独立嵌套类，避免与 @AutoConfigureMockMvc 冲突）；扫描本 it 包。 */
    @SpringBootApplication
    static class TestApp {
    }
}
