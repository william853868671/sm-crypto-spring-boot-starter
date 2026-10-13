package com.github.william853868671.smcrypto.crypto;

/**
 * SM2 密钥对（hex 裸格式）。
 *
 * <p>刻意不提供 {@code toString()} 打印私钥的实现，避免私钥被日志组件无意打出来。</p>
 */
public final class Sm2KeyPair {

    /** 130 位 hex 公钥（04 ‖ X ‖ Y） */
    private final String publicKey;
    /** 64 位 hex 私钥 */
    private final String privateKey;

    public Sm2KeyPair(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    /** 公钥可以公开，这里允许打印，便于联调时复制给前端。 */
    public String describePublic() {
        return "SM2 publicKey(hex)=" + publicKey;
    }

    @Override
    public String toString() {
        return "Sm2KeyPair{publicKey=" + publicKey + ", privateKey=*** 已隐藏 ***}";
    }
}
