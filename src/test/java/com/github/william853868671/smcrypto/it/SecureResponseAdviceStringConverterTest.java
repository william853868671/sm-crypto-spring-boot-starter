package com.github.william853868671.smcrypto.it;

import com.github.william853868671.smcrypto.crypto.SecureResponse;
import com.github.william853868671.smcrypto.crypto.Sm2KeyPair;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import com.github.william853868671.smcrypto.spring.SecureResponseAdvice;
import com.github.william853868671.smcrypto.spring.SecureResponseService;
import com.github.william853868671.smcrypto.spring.SmcfbProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 复现并守护「控制器返回 String 时崩溃」的修复：
 * 当 Spring 因原始返回类型是 String 而选中 {@link StringHttpMessageConverter}，
 * 把 body 换成 {@link SecureResponse} 对象会让该转换器抛 ClassCastException。
 * 修复后 should 把加密结构序列化成 JSON 字符串返回，且 content-type 为 application/json。
 */
class SecureResponseAdviceStringConverterTest {

    private SecureResponseAdvice newAdvice() {
        Sm2KeyPair frontendKp = SmCryptoUtil.generateSm2KeyPair();
        SmcfbProperties props = new SmcfbProperties();
        props.setEnabled(true);
        props.setClientPublicKey(frontendKp.getPublicKey());
        props.setRequireAnnotation(false);
        SecureResponseService svc = new SecureResponseService(props, SecureResponseService.standaloneObjectMapper());
        return new SecureResponseAdvice(svc, props);
    }

    private ServerHttpResponse mockResponse() {
        ServerHttpResponse r = mock(ServerHttpResponse.class);
        when(r.getHeaders()).thenReturn(new HttpHeaders());
        return r;
    }

    @Test
    void stringReturn_withStringConverter_returnsJsonStringNotObject() throws Exception {
        SecureResponseAdvice advice = newAdvice();

        Object result = advice.beforeBodyWrite(
                "plain text body",
                mock(MethodParameter.class),
                MediaType.TEXT_PLAIN,
                StringHttpMessageConverter.class,
                mock(ServerHttpRequest.class),
                mockResponse());

        // 必须是 String（JSON），不能是 SecureResponse 对象，否则 StringHttpMessageConverter 会 ClassCastException
        assertThat(result).isInstanceOf(String.class);
        JsonNode node = new ObjectMapper().readTree((String) result);
        assertThat(node.get("code").asInt()).isEqualTo(200);
        assertThat(node.get("data").asText()).isNotBlank();
        assertThat(node.get("key").asText()).isNotBlank();
    }

    @Test
    void alreadySecureResponse_withStringConverter_serializesWithoutDoubleEncrypt() throws Exception {
        SecureResponseAdvice advice = newAdvice();

        // 业务方自己包了 SecureResponse（key 非空代表已加密）
        Object result = advice.beforeBodyWrite(
                new SecureResponseService(new SmcfbProperties() {{
                    setEnabled(true);
                    setClientPublicKey(SmCryptoUtil.generateSm2KeyPair().getPublicKey());
                }}, SecureResponseService.standaloneObjectMapper()).success("x"),
                mock(MethodParameter.class),
                MediaType.TEXT_PLAIN,
                StringHttpMessageConverter.class,
                mock(ServerHttpRequest.class),
                mockResponse());

        assertThat(result).isInstanceOf(String.class);
        JsonNode node = new ObjectMapper().readTree((String) result);
        assertThat(node.get("code").asInt()).isEqualTo(200);
        assertThat(node.get("key").asText()).isNotBlank();
    }

    @Test
    void nonStringConverter_returnsSecureResponseObjectUnchanged() throws Exception {
        SecureResponseAdvice advice = newAdvice();

        // 其它转换器（如 Jackson）能写出对象，不应被序列化成字符串，保持原对象返回
        Object result = advice.beforeBodyWrite(
                "plain text body",
                mock(MethodParameter.class),
                MediaType.APPLICATION_JSON,
                Object.class, // 不是 StringHttpMessageConverter 的子类
                mock(ServerHttpRequest.class),
                mockResponse());

        assertThat(result).isInstanceOf(SecureResponse.class);
    }
}
