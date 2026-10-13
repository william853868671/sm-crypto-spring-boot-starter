package com.github.william853868671.smcrypto.samples;

import com.github.william853868671.smcrypto.crypto.SecureResponse;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import com.github.william853868671.smcrypto.spring.EncryptedResponse;
import com.github.william853868671.smcrypto.spring.SecureResponseService;
import com.github.william853868671.smcrypto.spring.SmCFBEncrypt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 演示接口。
 *
 * <ul>
 *   <li>{@code /api/order/{id}} —— 返回体加密（标了 {@link SmCFBEncrypt}，响应头带 {@code X-SmCFBEncrypt: true}）</li>
 *   <li>{@code /api/plain/order/{id}} —— 同样的数据，不加密，用于对比抓包效果</li>
 *   <li>{@code /api/health} —— 加密组件健康检查</li>
 *   <li>{@code /api/order/{id}/manual} —— 手动调用加密服务（不用注解的写法）</li>
 *   <li>{@code /api/order/{id}/legacy} —— 历史注解 {@link EncryptedResponse}，效果与 {@link SmCFBEncrypt} 一致</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    private final SecureResponseService secureResponseService;

    public DemoController(SecureResponseService secureResponseService) {
        this.secureResponseService = secureResponseService;
    }

    /** 返回体加密：业务代码只管返回对象，加密由 Advice 透明完成，响应头标记 X-SmCFBEncrypt=true。 */
    @SmCFBEncrypt
    @GetMapping("/order/{id}")
    public Map<String, Object> detail(@PathVariable Long id) {
        return mockOrder(id);
    }

    /** 历史注解写法，行为与 {@link SmCFBEncrypt} 完全一致（兼容保留）。 */
    @EncryptedResponse
    @GetMapping("/order/{id}/legacy")
    public Map<String, Object> legacyDetail(@PathVariable Long id) {
        return mockOrder(id);
    }

    /** 同样的数据不加密，可直接在浏览器里看到明文，便于对比。 */
    @GetMapping("/plain/order/{id}")
    public Map<String, Object> plainDetail(@PathVariable Long id) {
        return mockOrder(id);
    }

    /** 手动写法：不使用注解时，自己把结果包成加密返回体。 */
    @GetMapping("/order/{id}/manual")
    public SecureResponse manual(@PathVariable Long id) {
        return secureResponseService.success(mockOrder(id));
    }

    /** 健康检查：暴露加密开关状态，便于排查"前端解不开"到底是配置问题还是代码问题。 */
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("smAlgorithmSelfCheck", SmCryptoUtil.selfCheck());
        map.put("serverTime", LocalDateTime.now().toString());
        return map;
    }

    private Map<String, Object> mockOrder(Long id) {
        Map<String, Object> vo = new LinkedHashMap<>();
        vo.put("orderId", id);
        vo.put("orderNo", "SO20261012000" + id);
        vo.put("customerName", "东");
        vo.put("mobile", "13800001234");
        vo.put("amount", new BigDecimal("1999.00"));
        vo.put("status", "PAID");
        vo.put("createdAt", LocalDateTime.of(2026, 10, 12, 14, 30, 0));
        return vo;
    }
}
