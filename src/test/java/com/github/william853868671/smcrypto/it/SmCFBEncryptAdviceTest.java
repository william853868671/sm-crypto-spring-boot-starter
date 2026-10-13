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
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 验证 {@link com.github.william853868671.smcrypto.spring.SmCFBEncrypt}
 * （及兼容注解 {@link com.github.william853868671.smcrypto.spring.EncryptedResponse}）
 * 触发返回体加密并写入响应头 {@code X-SmCFBEncrypt: true}；以及入站请求解密：
 * 前端用后端公钥加密请求体并带该头时，后端自动解密后再交给 Controller。
 */
@SpringBootTest(classes = SmCFBEncryptAdviceTest.TestApp.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "smcfb.enabled=true",
        "smcfb.client-public-key=${sm.test.publicKey}",
        "smcfb.server-private-key=${sm.test.serverPrivateKey}",
        "smcfb.request-decrypt-enabled=true"
})
class SmCFBEncryptAdviceTest {

    static Sm2KeyPair frontendKp;
    static Sm2KeyPair backendKp;
    static {
        // 类加载期生成两套临时密钥：前端公钥注入 smcfb.client-public-key（响应加密）；
        // 后端私钥注入 smcfb.server-private-key（请求解密）。后端公钥用于测试里模拟前端加密请求。
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
    void smCFBEncrypt_setsHeaderAndEncryptsBody() throws Exception {
        MvcResult result = mockMvc.perform(get("/t/enc"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(SecureResponseAdvice.HEADER_ENCRYPTED))
                .isEqualTo("true");

        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(node.get("code").asInt()).isEqualTo(200);
        assertThat(node.get("data").asText()).isNotEqualTo("{\"k\":\"v\"}");
        assertThat(node.get("key").asText()).isNotBlank();
    }

    @Test
    void legacyEncryptedResponse_alsoSetsHeader() throws Exception {
        MvcResult result = mockMvc.perform(get("/t/legacy"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(SecureResponseAdvice.HEADER_ENCRYPTED))
                .isEqualTo("true");
    }

    @Test
    void noAnnotation_noHeader_noEncryption() throws Exception {
        MvcResult result = mockMvc.perform(get("/t/plain"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getHeader(SecureResponseAdvice.HEADER_ENCRYPTED)).isNull();
        assertThat(result.getResponse().getContentAsString()).contains("\"k\":\"v\"");
    }

    @Test
    void decryptRequest_decryptsEncryptedBody() throws Exception {
        // 前端视角：用【后端公钥】加密请求体，并对齐后端密文格式 {data, key}
        String plainJson = "{\"k\":\"v\"}";
        String sm4Key = SmCryptoUtil.generateSm4Key();
        String data = SmCryptoUtil.sm4Encrypt(plainJson, sm4Key);
        String key = SmCryptoUtil.sm2Encrypt(sm4Key, backendKp.getPublicKey());
        String requestBody = "{\"data\":\"" + data + "\",\"key\":\"" + key + "\"}";

        MvcResult result = mockMvc.perform(post("/t/echo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(SecureResponseAdvice.HEADER_ENCRYPTED, "true")
                        .content(requestBody))
                .andExpect(status().isOk())
                .andReturn();

        // 解密后 Controller 收到明文 {k:v}，原样回显即证明入站解密成功
        assertThat(result.getResponse().getContentAsString()).contains("\"k\":\"v\"");
    }

    @Test
    void noHeader_keepsEncryptedStructureUnchanged() throws Exception {
        String plainJson = "{\"k\":\"v\"}";
        String sm4Key = SmCryptoUtil.generateSm4Key();
        String data = SmCryptoUtil.sm4Encrypt(plainJson, sm4Key);
        String key = SmCryptoUtil.sm2Encrypt(sm4Key, backendKp.getPublicKey());
        String requestBody = "{\"data\":\"" + data + "\",\"key\":\"" + key + "\"}";

        MvcResult result = mockMvc.perform(post("/t/echo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody)) // 不带 X-SmCFBEncrypt 头
                .andExpect(status().isOk())
                .andReturn();

        // 未解密：Controller 直接收到 {data,key} 结构
        assertThat(result.getResponse().getContentAsString()).contains("\"data\"");
        assertThat(result.getResponse().getContentAsString()).doesNotContain("\"k\":\"v\"");
    }

    /** 测试用的 Spring Boot 配置类（独立嵌套类，避免与 @AutoConfigureMockMvc 冲突）；扫描本 it 包。 */
    @SpringBootApplication
    static class TestApp {
    }
}
