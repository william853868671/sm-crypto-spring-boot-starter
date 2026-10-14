package com.github.william853868671.smcrypto.spring;

import com.github.william853868671.smcrypto.crypto.SecureResponse;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * 默认对 {@code @RestController} 的返回体加密，除非接口显式标注 {@link SmCFBEncrypt}{@code (false)}。
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
    private final SmcfbProperties properties;

    public SecureResponseAdvice(SecureResponseService secureResponseService, SmcfbProperties properties) {
        this.secureResponseService = secureResponseService;
        this.properties = properties;
    }

    @Override
    public boolean supports(MethodParameter returnType, Class converterType) {
        // 显式关闭（value=false）永远不加密
        if (isEncryptDisabled(returnType)) {
            return false;
        }
        // require-annotation=true：只有显式标注了 @SmCFBEncrypt 才加密
        if (properties.isRequireAnnotation()) {
            return hasAnyEncryptAnnotation(returnType);
        }
        // 默认（require-annotation=false）：返回体默认即加密，不加注解也加密
        return true;
    }

    /**
     * 是否存在 {@link SmCFBEncrypt} 注解（方法级或类级）。
     * 仅用于 require-annotation 模式：据此判断该接口是否「被显式要求加密」。
     */
    private boolean hasAnyEncryptAnnotation(MethodParameter returnType) {
        if (returnType.hasMethodAnnotation(SmCFBEncrypt.class)) {
            return true;
        }
        Class<?> declaring = returnType.getContainingClass();
        return declaring != null && declaring.isAnnotationPresent(SmCFBEncrypt.class);
    }

    /**
     * 判断某个接口是否被显式关闭加密。
     *
     * <p>优先级：方法上的 {@link SmCFBEncrypt} 优先于类上同款注解；
     * 方法级出现了该注解（无论 true/false）就以方法级为准；方法级没有时再看法级。</p>
     */
    private boolean isEncryptDisabled(MethodParameter returnType) {
        SmCFBEncrypt methodSm = returnType.getMethodAnnotation(SmCFBEncrypt.class);
        if (methodSm != null) {
            return !methodSm.value();
        }
        Class<?> declaring = returnType.getContainingClass();
        if (declaring != null) {
            SmCFBEncrypt classSm = declaring.getAnnotation(SmCFBEncrypt.class);
            if (classSm != null) {
                return !classSm.value();
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
        SecureResponse sr;
        if (body instanceof SecureResponse) {
            sr = (SecureResponse) body;
        } else {
            try {
                sr = secureResponseService.success(body);
            } catch (RuntimeException e) {
                // 加密失败必须让调用方看见明确原因，而不是一个空 500
                sr = secureResponseService.buildOnError(
                        SecureResponseService.CODE_CRYPTO_ERROR, "返回体加密失败：" + e.getMessage());
            }
        }
        markIfEncrypted(response, sr);

        // 关键：当接口原始返回类型是 String 时，Spring 在 beforeBodyWrite 之前就已选中
        // StringHttpMessageConverter（它只能写 String）。若直接把 body 换成 SecureResponse 对象，
        // 该转换器写出的瞬间会在 addDefaultHeaders 处抛 ClassCastException。
        // 因此这里把加密结构序列化成 JSON 字符串再返回，并显式声明 content-type 为 application/json。
        if (StringHttpMessageConverter.class.isAssignableFrom(selectedConverterType)) {
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            return secureResponseService.toJsonString(sr);
        }
        return sr;
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
