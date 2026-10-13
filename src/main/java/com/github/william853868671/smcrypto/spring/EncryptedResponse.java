package com.github.william853868671.smcrypto.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 控制接口「返回体是否加密」的注解（历史注解，现已兼容 {@link SmCFBEncrypt}）。
 *
 * <p>可以标在方法上，也可以标在 Controller 类上（方法级优先于类级）。
 * 本 starter 对返回体<b>默认即加密</b>，因此本注解最常用于显式关闭：{@code @EncryptedResponse(false)}。
 * 新代码建议优先使用 {@link SmCFBEncrypt}；两者行为完全一致，可混用。</p>
 *
 * <pre>
 * &#64;RestController
 * public class OrderController {
 *
 *     &#64;EncryptedResponse(false)
 *     &#64;GetMapping("/api/callback")
 *     public Object callback() { ... }
 * }
 * </pre>
 *
 * @see SmCFBEncrypt
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptedResponse {
    /** 是否加密返回体，默认 {@code true}（与 {@link SmCFBEncrypt} 语义一致）。 */
    boolean value() default true;
}
