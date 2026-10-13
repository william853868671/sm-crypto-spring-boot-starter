package com.github.william853868671.smcrypto.it;

import com.github.william853868671.smcrypto.spring.EncryptedResponse;
import com.github.william853868671.smcrypto.spring.SmCFBEncrypt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 仅用于 {@link SmCFBEncryptAdviceTest} 的测试控制器，放在独立子包避免被组件扫描误伤库内 Bean。
 */
@RestController
@RequestMapping("/t")
public class AdviceTestController {

    @SmCFBEncrypt
    @GetMapping("/enc")
    public Map<String, Object> enc() {
        return sample();
    }

    @EncryptedResponse
    @GetMapping("/legacy")
    public Map<String, Object> legacy() {
        return sample();
    }

    @GetMapping("/plain")
    public Map<String, Object> plain() {
        return sample();
    }

    @PostMapping("/echo")
    public Map<String, Object> echo(@RequestBody Map<String, Object> body) {
        return body;
    }

    private Map<String, Object> sample() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("k", "v");
        return m;
    }
}
