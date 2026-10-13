package com.github.william853868671.smcrypto.crypto;

import java.io.Serializable;

/**
 * 加密返回体：{@code {"code":200,"data":"...","key":"..."}}
 *
 * <ul>
 *   <li>{@code code} —— 业务状态码，明文</li>
 *   <li>{@code data} —— 业务数据的 SM4 密文，{@code Base64(IV ‖ 密文)}</li>
 *   <li>{@code key}  —— 加密该 data 所用 SM4 密钥的 SM2 密文（hex，无 04 前缀）</li>
 * </ul>
 *
 * <p>data 与 key 必须成对使用：前端先用自己私钥解出 key，再用 key 解出 data。
 * 每次响应都会重新生成 SM4 密钥与 IV，因此同一份业务数据两次返回的密文完全不同。</p>
 */
public class SecureResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 业务状态码 */
    private int code;
    /** 业务数据密文：Base64(IV(16B) ‖ SM4-CBC 密文) */
    private String data;
    /** SM4 密钥的 SM2 密文：无 04 前缀的 C1C3C2 hex */
    private String key;

    public SecureResponse() {
    }

    public SecureResponse(int code, String data, String key) {
        this.code = code;
        this.data = data;
        this.key = key;
    }

    public static SecureResponse of(int code, String data, String key) {
        return new SecureResponse(code, data, key);
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public String toString() {
        return "SecureResponse{code=" + code + ", data=" + brief(data) + ", key=" + brief(key) + '}';
    }

    private static String brief(String s) {
        if (s == null || s.length() <= 16) {
            return s;
        }
        return s.substring(0, 16) + "...(" + s.length() + ")";
    }
}
