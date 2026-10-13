package com.github.william853868671.smcrypto.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标记「返回体需要加密」的接口（推荐注解，原名 {@link EncryptedResponse} 仍兼容）。
 *
 * <p>标在方法上或 Controller 类上均可：标在类上则类内所有接口都加密。
 * 标了之后，{@link SecureResponseAdvice} 会把返回值自动替换为加密返回体
 * {@code {"code":200,"data":"...","key":"..."}}，并在响应头写入
 * {@code X-SmCFBEncrypt: true} 告知前端「本响应体已加密」。</p>
 *
 * <p>加解密机制（一次一密）：每次响应随机生成一把 SM4 会话密钥与 IV，用【前端 SM2 公钥】
 * 加密该 SM4 密钥后随响应下发；前端用自身 SM2 私钥解出 SM4 密钥，再解出业务数据。
 * 私钥不出本端，是整套机制成立的前提。SM4 采用 CBC + 随机 IV（与前端 sm-crypto 互通）。</p>
 *
 * <pre>
 * &#64;RestController
 * public class OrderController {
 *
 *     &#64;SmCFBEncrypt
 *     &#64;GetMapping("/api/order/{id}")
 *     public OrderVO detail(&#64;PathVariable Long id) { ... }
 * }
 * </pre>
 *
 * @see SecureResponseAdvice
 * @see EncryptedResponse
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SmCFBEncrypt {
}
