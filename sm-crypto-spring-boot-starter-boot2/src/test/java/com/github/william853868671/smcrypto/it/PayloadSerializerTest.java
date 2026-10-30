package com.github.william853868671.smcrypto.it;

import com.github.william853868671.smcrypto.crypto.SecureResponse;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import com.github.william853868671.smcrypto.spring.PayloadSerializer;
import com.github.william853868671.smcrypto.spring.SecureResponseService;
import com.github.william853868671.smcrypto.spring.SmcfbProperties;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 守护「业务返回体（放进信封 data 字段的内容）走可插拔 PayloadSerializer」：
 * 默认用 Jackson；引用方注册自定义 Bean 后，加密体内业务对象的序列化方式随之改变。
 */
class PayloadSerializerTest {

    private SmcfbProperties propsWithKey() {
        SmcfbProperties p = new SmcfbProperties();
        p.setEnabled(true);
        p.setClientPublicKey(SmCryptoUtil.generateSm2KeyPair().getPublicKey());
        return p;
    }

    @Test
    void customSerializer_isInvokedForPayload() {
        AtomicReference<Object> captured = new AtomicReference<>();
        PayloadSerializer custom = obj -> {
            captured.set(obj);
            return "SERIALIZED_BY_CUSTOM";
        };

        SecureResponseService svc = new SecureResponseService(
                propsWithKey(), SecureResponseService.standaloneObjectMapper(), custom);

        svc.success(Collections.singletonMap("k", "v"));

        // 自定义序列化器必须被调用，且收到的正是业务对象
        assertThat(captured.get()).isEqualTo(Collections.singletonMap("k", "v"));
    }

    @Test
    void defaultJacksonSerializer_isUsedWhenNoCustom() {
        // 默认构造走 Jackson，行为与原先一致，不应抛异常
        SecureResponseService svc = new SecureResponseService(
                propsWithKey(), SecureResponseService.standaloneObjectMapper());
        SecureResponse sr = svc.success(Collections.singletonMap("k", "v"));
        assertThat(sr.getData()).isNotBlank();
        assertThat(sr.getKey()).isNotBlank();
    }
}
