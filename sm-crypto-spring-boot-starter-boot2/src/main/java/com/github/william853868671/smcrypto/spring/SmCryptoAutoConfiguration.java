package com.github.william853868671.smcrypto.spring;

import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import cn.hutool.core.util.StrUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * SM 国密返回体加密的自动配置。
 *
 * <p>引用方只需引入本 starter 并在 {@code application.yml} 里配置 {@code smcfb.client-public-key}，
 * {@code @RestController} 的返回体就会<b>默认自动加密</b>成 {@code {code,data,key}}，并附带响应头
 * {@code X-SmCFBEncrypt: true} 提示前端已加密；个别接口用 {@link SmCFBEncrypt}{@code (false)}
 * （用 {@link SmCFBEncrypt}{@code (false)}）即可显式走明文。</p>
 *
 * <ul>
 *   <li>默认启用（{@code smcfb.enabled=true}）；设为 {@code false} 则整套加密逻辑不生效，
 *       注解被忽略，接口照常返回明文，方便联调对比。</li>
 *   <li>启用且配置了 {@code failFast=true}（默认）时，公钥缺失或格式非法会在启动时直接失败，
 *       而不是等第一个请求进来才暴露问题。</li>
 * </ul>
 */
@AutoConfiguration
@EnableConfigurationProperties(SmcfbProperties.class)
public class SmCryptoAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SmCryptoAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public PayloadSerializer payloadSerializer(ObjectMapper objectMapper) {
        // 默认用项目注入的 Jackson ObjectMapper 序列化业务对象；
        // 引用方若想改用 fastjson2（让加密体内枚举也按 code 输出），注册一个同名 Bean 即可覆盖
        return new JacksonPayloadSerializer(objectMapper);
    }

    @Bean
    @ConditionalOnProperty(prefix = "smcfb", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SecureResponseService secureResponseService(SmcfbProperties properties,
                                                      ObjectMapper objectMapper,
                                                      PayloadSerializer payloadSerializer) {
        // 启动期自检：配置合法性 + 国密算法可用性（宁可启动失败，也不要带病上线）
        properties.validate();
        if (!SmCryptoUtil.selfCheck()) {
            throw new IllegalStateException("国密算法自检失败，请检查 bcprov / hutool 依赖是否完整");
        }
        String pk = properties.getClientPublicKey();
        if (pk != null && pk.length() > 18) {
            log.info("接口加密已启用，前端公钥 {}...{}（{} 位）",
                    pk.substring(0, 10), pk.substring(pk.length() - 8), pk.length());
        }
        return new SecureResponseService(properties, objectMapper, payloadSerializer);
    }

    @Bean
    @ConditionalOnProperty(prefix = "smcfb", name = "enabled", havingValue = "true", matchIfMissing = true)
    public SecureResponseAdvice secureResponseAdvice(SecureResponseService secureResponseService,
                                                     SmcfbProperties properties) {
        return new SecureResponseAdvice(secureResponseService, properties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "smcfb", name = "request-decrypt-enabled", havingValue = "true", matchIfMissing = true)
    public SmcfbDecryptAdvice smcfbDecryptAdvice(SmcfbProperties properties, ObjectMapper objectMapper) {
        properties.validate();
        String sk = properties.getServerPrivateKey();
        if (!StrUtil.isBlank(sk)) {
            String serverPub = SmCryptoUtil.derivePublicKey(sk);
            log.info("请求体解密已启用，后端公钥（提供给前端用于加密请求）{}...{}（{} 位）",
                    serverPub.substring(0, 10), serverPub.substring(serverPub.length() - 8), serverPub.length());
        }
        return new SmcfbDecryptAdvice(properties, objectMapper);
    }
}
