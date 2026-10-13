package com.github.william853868671.smcrypto.spring;

import com.github.william853868671.smcrypto.crypto.SecureResponse;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * 把标了 {@link SmCFBEncrypt} / {@link EncryptedResponse} 的接口返回值自动替换为加密返回体。
 *
 * <p>Controller 里照常返回业务对象，加密这件事对业务代码透明 —— 不用每个方法手写
 * {@code secureResponseService.success(...)}，也就不会有人漏写。</p>
 *
 * <p>只要响应体被加密（{@code key} 非空），都会同时写入响应头
 * {@code X-SmCFBEncrypt: true}，前端据此判断是否需要走解密流程。</p>
 */
@RestControllerAdvice
public class SecureResponseAdvice implements ResponseBodyAdvice<Object> {

    /** 响应头：值为 {@code true} 代表本响应体已加密（{@code {code,data,key}}）。前端据此决定是否解密。 */
    public static final String HEADER_ENCRYPTED = "X-SmCFBEncrypt";

    private final SecureResponseService secureResponseService;

    public SecureResponseAdvice(SecureResponseService secureResponseService) {
        this.secureResponseService = secureResponseService;
    }

    @Override
    public boolean supports(MethodParameter returnType, Class converterType) {
        return hasEncryptAnnotation(returnType);
    }

    private boolean hasEncryptAnnotation(MethodParameter returnType) {
        if (returnType.hasMethodAnnotation(SmCFBEncrypt.class)
                || returnType.hasMethodAnnotation(EncryptedResponse.class)) {
            return true;
        }
        Class<?> declaring = returnType.getContainingClass();
        return declaring != null
                && (declaring.isAnnotationPresent(SmCFBEncrypt.class)
                    || declaring.isAnnotationPresent(EncryptedResponse.class));
    }

    @Override
    public Object beforeBodyWrite(Object body,
                                  MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class selectedConverterType,
                                  ServerHttpRequest request,
                                  ServerHttpResponse response) {
        // 业务代码自己调了 service，已经是加密返回体：不再重复加密，但需标记 header
        if (body instanceof SecureResponse) {
            markIfEncrypted(response, (SecureResponse) body);
            return body;
        }
        try {
            SecureResponse sr = secureResponseService.success(body);
            markIfEncrypted(response, sr);
            return sr;
        } catch (RuntimeException e) {
            // 加密失败必须让调用方看见明确原因，而不是一个空 500
            SecureResponse sr = secureResponseService.buildOnError(
                    SecureResponseService.CODE_CRYPTO_ERROR, "返回体加密失败：" + e.getMessage());
            markIfEncrypted(response, sr);
            return sr;
        }
    }

    /**
     * 仅在响应体确实被加密（SM4 密钥的 SM2 密文非空）时写入标记头。
     * 若加密被关闭（{@code smcfb.enabled=false}，此时 key 为 null）则不写，避免误导前端。
     */
    private void markIfEncrypted(ServerHttpResponse response, SecureResponse sr) {
        if (sr.getKey() != null) {
            response.getHeaders().set(HEADER_ENCRYPTED, "true");
        }
    }
}
