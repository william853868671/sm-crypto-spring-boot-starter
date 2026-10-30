package com.github.william853868671.smcrypto.it;

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

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 守护「按路径排除不加密」能力（{@code smcfb.exclude-paths}）：
 * 命中排除模式的接口原样返回、不写 {@code X-SmCFBEncrypt} 头；未命中的接口照常加密。
 */
class SecureResponseAdviceExcludePathTest {

    private SecureResponseAdvice newAdvice(List<String> excludePaths) {
        Sm2KeyPair frontendKp = SmCryptoUtil.generateSm2KeyPair();
        SmcfbProperties props = new SmcfbProperties();
        props.setEnabled(true);
        props.setClientPublicKey(frontendKp.getPublicKey());
        props.setRequireAnnotation(false);
        props.setExcludePaths(excludePaths);
        SecureResponseService svc = new SecureResponseService(props, SecureResponseService.standaloneObjectMapper());
        return new SecureResponseAdvice(svc, props);
    }

    private ServerHttpResponse mockResponse(HttpHeaders headers) {
        ServerHttpResponse r = mock(ServerHttpResponse.class);
        when(r.getHeaders()).thenReturn(headers);
        return r;
    }

    private ServerHttpRequest req(String path) {
        ServerHttpRequest r = mock(ServerHttpRequest.class);
        when(r.getURI()).thenReturn(URI.create(path));
        return r;
    }

    @Test
    void excludedPath_returnsBodyUnchanged_andNoHeader() throws Exception {
        SecureResponseAdvice advice = newAdvice(Arrays.asList("/v3/api-docs/**", "/swagger-ui/**"));
        HttpHeaders headers = new HttpHeaders();

        Object result = advice.beforeBodyWrite(
                "{\"openapi\":\"3.0\"}",
                mock(MethodParameter.class),
                MediaType.APPLICATION_JSON,
                Object.class,
                req("/v3/api-docs"),
                mockResponse(headers));

        assertThat(result).isEqualTo("{\"openapi\":\"3.0\"}");
        assertThat(headers).doesNotContainKey(SecureResponseAdvice.HEADER_ENCRYPTED);
    }

    @Test
    void excludedPath_subPath_alsoSkipped() throws Exception {
        SecureResponseAdvice advice = newAdvice(Arrays.asList("/v3/api-docs/**"));
        HttpHeaders headers = new HttpHeaders();

        Object result = advice.beforeBodyWrite(
                "doc",
                mock(MethodParameter.class),
                MediaType.TEXT_PLAIN,
                StringHttpMessageConverter.class,
                req("/v3/api-docs/groupA"),
                mockResponse(headers));

        assertThat(result).isEqualTo("doc");
        assertThat(headers).doesNotContainKey(SecureResponseAdvice.HEADER_ENCRYPTED);
    }

    @Test
    void nonExcludedPath_stillEncrypts() throws Exception {
        SecureResponseAdvice advice = newAdvice(Arrays.asList("/v3/api-docs/**"));
        HttpHeaders headers = new HttpHeaders();

        Object result = advice.beforeBodyWrite(
                "plain",
                mock(MethodParameter.class),
                MediaType.TEXT_PLAIN,
                StringHttpMessageConverter.class,
                req("/api/order/1"),
                mockResponse(headers));

        assertThat(result).isInstanceOf(String.class);
        JsonNode node = new ObjectMapper().readTree((String) result);
        assertThat(node.get("code").asInt()).isEqualTo(200);
        assertThat(node.get("key").asText()).isNotBlank();
        assertThat(headers.getFirst(SecureResponseAdvice.HEADER_ENCRYPTED)).isEqualTo("true");
    }

    @Test
    void emptyExcludePaths_encryptsEverything() throws Exception {
        SecureResponseAdvice advice = newAdvice(null);
        HttpHeaders headers = new HttpHeaders();

        Object result = advice.beforeBodyWrite(
                "doc",
                mock(MethodParameter.class),
                MediaType.TEXT_PLAIN,
                StringHttpMessageConverter.class,
                req("/v3/api-docs"),
                mockResponse(headers));

        assertThat(result).isInstanceOf(String.class);
        JsonNode node = new ObjectMapper().readTree((String) result);
        assertThat(node.get("key").asText()).isNotBlank();
    }
}
