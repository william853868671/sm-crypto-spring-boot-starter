package com.github.william853868671.smcrypto.spring;

import com.github.william853868671.smcrypto.crypto.SecureResponse;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;

/**
 * 返回体加密服务 —— 用户方案中的第 1、2、4 步都在这里落地：
 *
 * <pre>
 *   1. 生成一把一次性的动态 SM4 密钥 Ks
 *   2. 用 Ks 加密返回体（业务数据的 JSON）
 *   3. 用前端的 SM2 公钥加密 Ks
 *   4. 组装成 {code, data, key} 返回
 * </pre>
 *
 * <p>每次响应都重新生成 Ks 与 IV，因此同一份业务数据两次返回的密文完全不同，
 * 攻击者无法通过比对密文推断业务内容。前端需要用自己的 SM2 私钥解出 Ks，
 * 再用 Ks 解出业务数据 —— 私钥不出本端，这是整套机制成立的前提。</p>
 *
 * <h3>为什么用 Jackson 而不是更省事的 Hutool JSON</h3>
 * Hutool 的 {@code JSONUtil.toJsonStr} 会把 {@code BigDecimal("1999.00")} 序列化成
 * {@code 1999}，金额尾数被抹掉；Jackson 默认保留 {@code 1999.00}。
 * 接口返回值里出现金额、数量、单价这类字段时，这种差异会直接变成对账事故。
 */
public class SecureResponseService {

    private static final Logger log = LoggerFactory.getLogger(SecureResponseService.class);

    /** 业务成功码 */
    public static final int CODE_SUCCESS = 200;
    /** 加密环节异常码 */
    public static final int CODE_CRYPTO_ERROR = 500;

    private final SmcfbProperties properties;
    private final ObjectMapper objectMapper;
    private final PayloadSerializer payloadSerializer;

    public SecureResponseService(SmcfbProperties properties, ObjectMapper objectMapper) {
        this(properties, objectMapper, new JacksonPayloadSerializer(objectMapper));
    }

    public SecureResponseService(SmcfbProperties properties, ObjectMapper objectMapper,
                                 PayloadSerializer payloadSerializer) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.payloadSerializer = payloadSerializer != null
                ? payloadSerializer : new JacksonPayloadSerializer(objectMapper);
    }

    /**
     * 脱离 Spring 容器时使用的 ObjectMapper（单元测试、命令行工具）。
     * 与 Spring Boot 默认配置保持一致：保留 BigDecimal 尾数、时间用 ISO-8601 而非时间戳。
     */
    public static ObjectMapper standaloneObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }

    /**
     * 加密成功返回体。
     *
     * @param payload 业务数据对象，会被序列化为 JSON 后加密
     */
    public SecureResponse success(Object payload) {
        return build(CODE_SUCCESS, payload);
    }

    /**
     * 加密指定状态码的返回体。
     */
    public SecureResponse build(int code, Object payload) {
        if (!properties.isEnabled()) {
            // 关闭加密时保持同样的响应结构，前端代码无需改动
            return SecureResponse.of(code, toJson(payload), null);
        }
        String json = toJson(payload);
        String sm4Key = SmCryptoUtil.generateSm4Key();
        String encryptedData = SmCryptoUtil.sm4Encrypt(json, sm4Key);
        String encryptedKey = SmCryptoUtil.sm2Encrypt(sm4Key, properties.getClientPublicKey());
        return SecureResponse.of(code, encryptedData, encryptedKey);
    }

    /**
     * 加密异常时的兜底返回。加密过程本身失败时不能再抛异常，否则用户看到的是通用 500 页面，
     * 根本不知道是加密配置出了问题。
     */
    public SecureResponse buildOnError(int code, String message) {
        try {
            return build(code, Collections.singletonMap("error", message));
        } catch (RuntimeException e) {
            log.error("返回体加密失败，降级为明文错误响应", e);
            return SecureResponse.of(CODE_CRYPTO_ERROR, message, null);
        }
    }

    /**
     * 序列化为 JSON。字符串直接透传，避免出现「JSON 字符串再被加引号」的双重转义。
     */
    protected String toJson(Object payload) {
        if (payload == null) {
            return "null";
        }
        if (payload instanceof CharSequence) {
            return payload.toString();
        }
        try {
            return payloadSerializer.serialize(payload);
        } catch (IOException e) {
            throw new IllegalStateException("返回体序列化失败：" + e.getMessage(), e);
        }
    }

    /**
     * 把已组装好的加密返回体序列化为 JSON 字符串。
     *
     * <p>用于「控制器原始返回类型是 {@code String}、Spring 因此选中了
     * {@link org.springframework.http.converter.StringHttpMessageConverter}」的场景：
     * 该转换器只能写出 {@code String}，无法写出 {@link SecureResponse} 对象
     * （否则会在 {@code StringHttpMessageConverter.addDefaultHeaders} 处抛出
     * {@code ClassCastException}）。Advice 里先把加密结构序列化成 JSON 字符串再返回，
     * 并显式声明 content-type 为 {@code application/json}。</p>
     */
    public String toJsonString(SecureResponse sr) {
        try {
            return objectMapper.writeValueAsString(sr);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("加密返回体序列化失败：" + e.getOriginalMessage(), e);
        }
    }
}
