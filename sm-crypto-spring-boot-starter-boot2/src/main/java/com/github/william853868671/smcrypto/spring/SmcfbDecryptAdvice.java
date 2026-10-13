package com.github.william853868671.smcrypto.spring;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import cn.hutool.core.util.StrUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

/**
 * 入站请求体解密 —— 与 {@link SecureResponseAdvice}（出战响应加密）对称：
 *
 * <p>前端用【本服务的 SM2 公钥】加密请求体，并在请求头带上 {@code X-SmCFBEncrypt: true} 时，
 * 本 Advice 在 {@code beforeBodyRead} 阶段透明地把密文还原成明文 JSON，再交给 Controller 的
 * {@code @RequestBody} 参数。业务代码就像处理明文一样，完全无感。</p>
 *
 * <pre>
 *   请求体密文结构（与响应一致）：
 *     {"data": "Base64(IV ‖ SM4-CBC密文)", "key": "SM4密钥的SM2密文(hex,无04前缀)"}
 *   解密步骤：
 *     1. key  = SM2 私钥解密(server-private-key)  → 还原 SM4 密钥
 *     2. data = SM4 解密(key)                     → 还原业务 JSON 明文
 * </pre>
 *
 * <p>只有请求头明确为 {@code true} 且已配置 {@code smcfb.server-private-key} 时才解密；
 * 否则原样放行，普通明文请求不受影响。</p>
 */
@ControllerAdvice
public class SmcfbDecryptAdvice implements RequestBodyAdvice {

    private static final Logger log = LoggerFactory.getLogger(SmcfbDecryptAdvice.class);

    /** 请求头：前端用本服务公钥加密请求体时置为 true。与响应加密共用同一标记头。 */
    public static final String HEADER_ENCRYPTED = SecureResponseAdvice.HEADER_ENCRYPTED;

    private final SmcfbProperties properties;
    private final ObjectMapper objectMapper;

    public SmcfbDecryptAdvice(SmcfbProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean supports(MethodParameter methodParameter, Type targetType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        // 对所有 @RequestBody 生效；是否真正解密在 beforeBodyRead 内按 header 判断
        return true;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter methodParameter,
                                           Type targetType,
                                           Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        String flag = inputMessage.getHeaders().getFirst(HEADER_ENCRYPTED);
        if (!properties.isRequestDecryptEnabled() || !"true".equalsIgnoreCase(flag)) {
            return inputMessage;
        }
        byte[] raw = StreamUtils.copyToByteArray(inputMessage.getBody());
        if (raw.length == 0) {
            return inputMessage;
        }
        String text = new String(raw, StandardCharsets.UTF_8);
        try {
            if (StrUtil.isBlank(properties.getServerPrivateKey())) {
                throw new HttpMessageNotReadableException(
                        "请求体已声明加密（X-SmCFBEncrypt: true）但未配置 smcfb.server-private-key，"
                                + "无法解密。如需解密请求，请配置后端 SM2 私钥。", inputMessage);
            }
            JsonNode node = objectMapper.readTree(text);
            JsonNode data = node.get("data");
            JsonNode key = node.get("key");
            if (data == null || key == null || data.isNull() || key.isNull()) {
                throw new HttpMessageNotReadableException(
                        "加密请求体缺少 data/key 字段，无法解密", inputMessage);
            }
            String sm4Key = SmCryptoUtil.sm2Decrypt(key.asText(), properties.getServerPrivateKey());
            String plainJson = SmCryptoUtil.sm4Decrypt(data.asText(), sm4Key);

            HttpHeaders headers = new HttpHeaders();
            headers.putAll(inputMessage.getHeaders());
            headers.remove(HttpHeaders.CONTENT_LENGTH);
            return new DecryptedInputMessage(headers,
                    new ByteArrayInputStream(plainJson.getBytes(StandardCharsets.UTF_8)));
        } catch (HttpMessageNotReadableException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new HttpMessageNotReadableException(
                    "请求体解密失败：" + e.getMessage(), inputMessage);
        }
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter methodParameter,
                                Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter methodParameter,
                                  Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    /** 包装解密后的明文，供后续 HttpMessageConverter 读取。 */
    private static final class DecryptedInputMessage implements HttpInputMessage {
        private final HttpHeaders headers;
        private final InputStream body;

        private DecryptedInputMessage(HttpHeaders headers, InputStream body) {
            this.headers = headers;
            this.body = body;
        }

        @Override
        public InputStream getBody() {
            return body;
        }

        @Override
        public HttpHeaders getHeaders() {
            return headers;
        }
    }
}
