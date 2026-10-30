package com.github.william853868671.smcrypto.spring;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * 基于 Jackson 的默认 {@link PayloadSerializer} 实现。使用项目注入的 {@link ObjectMapper}，
 * 以尊重项目自身的 Jackson 配置（日期格式、null 处理等）。
 */
public class JacksonPayloadSerializer implements PayloadSerializer {

    private final ObjectMapper objectMapper;

    public JacksonPayloadSerializer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String serialize(Object payload) throws IOException {
        return objectMapper.writeValueAsString(payload);
    }
}
