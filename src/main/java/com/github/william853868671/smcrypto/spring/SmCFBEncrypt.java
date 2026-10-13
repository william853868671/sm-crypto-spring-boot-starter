package com.github.william853868671.smcrypto.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 控制接口「返回体是否加密」的注解（推荐注解，原名 {@link EncryptedResponse} 仍兼容）。
 *
 * <p><b>默认即加密</b>：本 starter 对 {@code @RestController} 的返回体默认全部加密，
 * 因此本注解最常用的写法是「显式关闭」某个接口 —— 即 {@code @SmCFBEncrypt(false)}。
 * 其它情况（不加注解、或 {@code @SmCFBEncrypt(true)}）都会按加密返回。</p>
 *
 * <p>标在方法上或 Controller 类上均可：方法级注解优先于类级注解。标在类上且为
 * {@code true} 时，类内所有接口都加密；标为 {@code false} 时整类跳过加密；
 * 类上 {@code false}、但某个方法又标 {@code true} 时，以方法级为准。</p>
 *
 * <p>只要响应体被加密，{@link SecureResponseAdvice} 就会把返回值自动替换为加密返回体
 * {@code {"code":200,"data":"...","key":"..."}}，并写入响应头
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
 *     &#64;GetMapping("/api/public/health")   // 默认加密
 *     public String health() { ... }
 *
 *     &#64;SmCFBEncrypt(false)                 // 显式关闭：明文返回
 *     &#64;GetMapping("/api/callback")
 *     public Object callback() { ... }
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
    /**
     * 该接口是否加密返回体。
     *
     * <ul>
     *   <li>{@code true}（默认）：加密返回体（等同只写 {@code @SmCFBEncrypt} 不加值）。</li>
     *   <li>{@code false}：不加密，按 Spring 默认方式原样序列化返回。
     *       用于健康检查、回调、第三方对接等「必须明文」的接口。</li>
     * </ul>
     */
    boolean value() default true;
}
