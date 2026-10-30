package com.github.william853868671.smcrypto.spring;

import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 接口加密配置。
 *
 * <pre>
 * smcfb:
 *   enabled: true
 *   client-public-key: 04a1b2c3...   # 前端（小程序）的 SM2 公钥，130 位 hex
 *   server-private-key: d4e5f6...    # 后端（本服务）SM2 私钥，64 位 hex，用于解密前端加密的请求
 *   request-decrypt-enabled: true    # 是否解密前端加密的请求体（前端带 X-SmCFBEncrypt: true 时）
 * </pre>
 */
@ConfigurationProperties(prefix = "smcfb")
public class SmcfbProperties {

    /** 是否启用返回体加密。联调期可置 false 直接看明文。 */
    private boolean enabled = true;

    /**
     * 是否必须显式标注 {@code @SmCFBEncrypt} 才加密返回体。
     *
     * <p>对应配置 {@code smcfb.require-annotation}。默认 {@code false}：返回体<b>默认即加密</b>——
     * 不加注解也加密，只有 {@code (false)} 才关掉。</p>
     *
     * <p>设为 {@code true} 时切换为「显式标注才加密」模式：只有标了注解（且值不为 {@code false}）的接口
     * 才加密，没标的接口一律明文返回。适合「仅个别接口需要加密、绝大多数接口保持明文」的场景。</p>
     */
    private boolean requireAnnotation = false;

    /**
     * 命中这些路径（Ant 风格）的接口<b>不加密</b>，原样明文返回，且不写 {@code X-SmCFBEncrypt} 头。
     *
     * <p>对应配置 {@code smcfb.exclude-paths}（List）。典型用途：Swagger/Knife4j 文档接口
     * （{@code /v3/api-docs/**}、{@code /swagger-ui/**}）、{@code /error}、Actuator（{@code /actuator/**}）、
     * 健康检查等「必须由浏览器/工具直连、不能加密」的端点。</p>
     *
     * <p>命中即整体跳过加密，比给每个端点逐个标 {@code @SmCFBEncrypt(false)} 更省事，
     * 也比 {@code require-annotation=true} 更轻——后者会改变「默认即加密」的整体模型。
     * 路径按请求 URI 的 path 部分做 Ant 匹配（{@code **} 匹配多级）。默认空，即不排除任何接口。</p>
     */
    private List<String> excludePaths = new ArrayList<>();

    /**
     * 前端公钥（130 位 hex，04 开头）。
     *
     * <p>后端用它对每次响应随机生成的 SM4 密钥做 SM2 加密。前端持有配对私钥才能解开，
     * 因此这里是「前端公钥」而不是后端自己的公钥。私钥永远不下发、不落服务端配置文件。</p>
     */
    private String clientPublicKey;

    /** 启动时是否校验公钥格式，格式非法直接启动失败，比线上报错好排查。 */
    private boolean failFast = true;

    /**
     * 是否解密前端加密的请求体。
     *
     * <p>前端用【本服务的 SM2 公钥】加密请求体、并在请求头带上 {@code X-SmCFBEncrypt: true}
     * 时，本服务自动用 {@link #serverPrivateKey} 解出明文后再交给 Controller。
     * 默认 true；联调期可置 false，直接收明文请求。</p>
     */
    private boolean requestDecryptEnabled = true;

    /**
     * 后端（本服务）SM2 私钥，64 位 hex。
     *
     * <p>用于解密前端用本服务公钥加密的请求：前端持有本服务公钥加密、本服务用此私钥解开。
     * 这是后端自己的私钥，<b>绝不外泄、绝不下发给前端</b>；前端需要的是与之配对的公钥
     * （可用 {@code SmCryptoUtil.derivePublicKey(serverPrivateKey)} 推导，或运行 GenKeyPairTool 一并生成）。</p>
     */
    private String serverPrivateKey;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isRequireAnnotation() {
        return requireAnnotation;
    }

    public void setRequireAnnotation(boolean requireAnnotation) {
        this.requireAnnotation = requireAnnotation;
    }

    public List<String> getExcludePaths() {
        return excludePaths;
    }

    public void setExcludePaths(List<String> excludePaths) {
        this.excludePaths = excludePaths;
    }

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public boolean isFailFast() {
        return failFast;
    }

    public void setFailFast(boolean failFast) {
        this.failFast = failFast;
    }

    public boolean isRequestDecryptEnabled() {
        return requestDecryptEnabled;
    }

    public void setRequestDecryptEnabled(boolean requestDecryptEnabled) {
        this.requestDecryptEnabled = requestDecryptEnabled;
    }

    public String getServerPrivateKey() {
        return serverPrivateKey;
    }

    public void setServerPrivateKey(String serverPrivateKey) {
        this.serverPrivateKey = serverPrivateKey;
    }

    /**
     * 配置自检：启用了某项加密能力却未配置合法密钥时，启动时直接失败，比线上报错好排查。
     */
    public void validate() {
        if (!failFast) {
            return;
        }
        if (enabled) {
            String pk = clientPublicKey == null ? "" : clientPublicKey.trim();
            if (pk.isEmpty()) {
                throw new IllegalStateException("smcfb.enabled=true 但未配置 smcfb.client-public-key，"
                        + "请先运行 GenKeyPairTool 生成【前端密钥对】，把前端公钥填到这里");
            }
            if (pk.length() != SmCryptoUtil.SM2_PUBLIC_KEY_HEX_LENGTH || !pk.startsWith("04")) {
                throw new IllegalStateException("smcfb.client-public-key 非法：应为 "
                        + SmCryptoUtil.SM2_PUBLIC_KEY_HEX_LENGTH + " 位 hex 且以 04 开头，实际长度 " + pk.length());
            }
        }
        if (requestDecryptEnabled) {
            String sk = serverPrivateKey == null ? "" : serverPrivateKey.trim();
            // 为空不 fail-fast：未配置 server-private-key 时仍可启动（仅做响应加密）；
            // 真正收到前端加密请求（X-SmCFBEncrypt: true）时再由 SmcfbDecryptAdvice 运行期明确报错。
            if (!sk.isEmpty() && sk.length() != SmCryptoUtil.SM2_PRIVATE_KEY_HEX_LENGTH) {
                throw new IllegalStateException("smcfb.server-private-key 非法：应为 "
                        + SmCryptoUtil.SM2_PRIVATE_KEY_HEX_LENGTH + " 位 hex（32 字节），实际长度 " + sk.length());
            }
        }
    }
}
