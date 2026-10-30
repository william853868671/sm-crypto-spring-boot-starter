package com.github.william853868671.smcrypto.spring;

import java.io.IOException;

/**
 * 业务返回体的序列化器 —— 仅作用于放进加密信封 {@code data} 字段的「业务对象」，不作用于信封本身。
 *
 * <p>默认实现 {@link JacksonPayloadSerializer} 使用项目注入的 Jackson {@code ObjectMapper}，
 * 因此行为与原先完全一致（枚举默认按 Jackson 规则序列化为枚举名）。</p>
 *
 * <p>若引用方希望业务对象按其它规则序列化（例如项目整体使用 fastjson2，且枚举配置了「枚举→code」），
 * 只需注册一个实现本接口的 Bean，库会通过 {@code @ConditionalOnMissingBean} 自动采用你的实现，
 * 从而让「加密体内的业务对象」与「项目中其它普通接口」使用同一套序列化规则，消除 name / code 差异。</p>
 */
@FunctionalInterface
public interface PayloadSerializer {

    /**
     * 把业务对象序列化为字符串（将被进一步加密后放入信封 data 字段）。
     *
     * @param payload 业务数据对象（非 null、非 CharSequence；String/CharSequence 由调用方提前透传）
     * @return 序列化后的字符串
     * @throws IOException 序列化失败
     */
    String serialize(Object payload) throws IOException;
}
