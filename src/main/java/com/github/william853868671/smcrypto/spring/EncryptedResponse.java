package com.github.william853868671.smcrypto.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标记「返回体需要加密」的接口（历史注解，现已兼容 {@link SmCFBEncrypt}）。
 *
 * <p>可以标在方法上，也可以标在 Controller 类上（类上标了则类内所有接口都加密）。
 * 新代码建议优先使用 {@link SmCFBEncrypt}；两者行为完全一致，可混用。</p>
 *
 * <pre>
 * &#64;RestController
 * public class OrderController {
 *
 *     &#64;EncryptedResponse
 *     &#64;GetMapping("/api/order/{id}")
 *     public OrderVO detail(&#64;PathVariable Long id) { ... }
 * }
 * </pre>
 *
 * @see SmCFBEncrypt
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptedResponse {
}
