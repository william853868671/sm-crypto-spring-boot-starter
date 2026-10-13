package com.github.william853868671.smcrypto.spring;

import com.github.william853868671.smcrypto.crypto.SecureResponse;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * 默认对 {@code @RestController} 的返回体加密，除非接口显式标注 {@link SmCFBEncrypt}{@code (false)}
 * 或 {@link EncryptedResponse}{@code (false)}。
 *
 * <p>加密是默认行为（不加注解即加密），因此本 Advice 对绝大多数接口都生效；
 * 业务代码照常返回业务对象，加密对业务透明 —— 不用每个方法手写
 * {@code secureResponseService.success(...)}，也就不会有人漏写。
 * 只有明确「必须明文」的接口（健康检查、回调、第三方对接等）才需要标 {@code (false)} 关掉。</p>
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
        // 默认加密：不加注解、或注解值为 true（默认值）都走加密；
        // 只有显式标了 value=false 的接口才跳过。方法级注解优先于类级注解。
        return !isEncryptDisabled(returnType);
    }

    /**
     * 判断某个接口是否被显式关闭加密。
     *
     * <p>优先级：方法上的 {@link SmCFBEncrypt} / {@link EncryptedResponse} 优先于类上同款注解；
     * 只要方法级出现了其中一个（无论 true/false），就以方法级为准；方法级没有时再看法级。</p>
     */
    private boolean isEncryptDisabled(MethodParameter returnType) {
        SmCFBEncrypt methodSm = returnType.getMethodAnnotation(SmCFBEncrypt.class);
        if (methodSm != null) {
            return !methodSm.value();
        }
        EncryptedResponse methodLegacy = returnType.getMethodAnnotation(EncryptedResponse.class);
        if (methodLegacy != null) {
            return !methodLegacy.value();
        }
        Class<?> declaring = returnType.getContainingClass();
        if (declaring != null) {
            SmCFBEncrypt classSm = declaring.getAnnotation(SmCFBEncrypt.class);
            if (classSm != null) {
                return !classSm.value();
            }
            EncryptedResponse classLegacy = declaring.getAnnotation(EncryptedResponse.class);
            if (classLegacy != null) {
                return !classLegacy.value();
            }
        }
        return false;
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
