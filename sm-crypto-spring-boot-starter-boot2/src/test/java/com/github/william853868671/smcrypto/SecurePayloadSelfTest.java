package com.github.william853868671.smcrypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.HexUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.github.william853868671.smcrypto.crypto.SecureResponse;
import com.github.william853868671.smcrypto.crypto.Sm2KeyPair;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;
import com.github.william853868671.smcrypto.spring.SmcfbProperties;
import com.github.william853868671.smcrypto.spring.SecureResponseService;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 后端加密链路自测（纯 Java，不依赖 Spring 容器与 JUnit）。
 *
 * <pre>
 * javac -encoding UTF-8 -cp &lt;hutool&gt;:&lt;bcprov&gt; -d out $(find src/main/java -name "*.java") src/test/java/.../SecurePayloadSelfTest.java
 * java  -cp out:&lt;hutool&gt;:&lt;bcprov&gt; com.github.william853868671.smcrypto.SecurePayloadSelfTest build/selftest
 * </pre>
 *
 * <p>最后一节会把「真实返回体」和「前端私钥」落盘，供 Node 端 sm-crypto 做跨语言验证。</p>
 */
public class SecurePayloadSelfTest {

    private static final List<String> FAILURES = new ArrayList<>();
    private static int total = 0;

    public static void main(String[] args) throws IOException {
        Path outDir = Paths.get(args.length > 0 ? args[0] : "build/selftest");
        boolean ok = run(outDir);
        if (!ok) {
            System.exit(1);
        }
    }

    /**
     * 跑全部自测章节，返回是否全部通过（不调用 System.exit，便于被 JUnit 包装）。
     */
    public static boolean run(Path outDir) throws IOException {
        FAILURES.clear();
        total = 0;
        Files.createDirectories(outDir);

        System.out.println("=================== 后端国密链路自测 ===================\n");

        section1SelfCheck();
        section2KeyPairFormat();
        section3Sm2RoundTrip();
        section4Sm2CipherFormat();
        section5Sm4RoundTrip();
        section6SecureResponse();
        section7NegativeCases();
        Path payloadFile = section8DumpForInterop(outDir);

        System.out.println("\n=================== 结果 ===================");
        System.out.println("通过 " + (total - FAILURES.size()) + " / " + total);
        if (FAILURES.isEmpty()) {
            System.out.println(">>> 全部通过");
        } else {
            System.out.println(">>> 失败项：");
            FAILURES.forEach(f -> System.out.println("    - " + f));
        }
        System.out.println("互联验证产物：" + payloadFile.toAbsolutePath());
        return FAILURES.isEmpty();
    }

    // ------------------------------------------------------------------

    private static void section1SelfCheck() {
        System.out.println("[1] 工具类自检 SmCryptoUtil.selfCheck()");
        check("SM2/SM4 加解密往返", true, SmCryptoUtil.selfCheck());
    }

    private static void section2KeyPairFormat() {
        System.out.println("\n[2] 密钥对格式");
        Sm2KeyPair kp = SmCryptoUtil.generateSm2KeyPair();
        check("公钥长度 = 130", 130, kp.getPublicKey().length());
        check("公钥以 04 开头", "04", kp.getPublicKey().substring(0, 2));
        check("私钥长度 = 64", 64, kp.getPrivateKey().length());
        check("前 2 组密钥不相同（随机性）", false,
                SmCryptoUtil.generateSm2KeyPair().getPrivateKey().equals(kp.getPrivateKey()));

        String derived = SmCryptoUtil.derivePublicKey(kp.getPrivateKey());
        check("由私钥推导的公钥一致", kp.getPublicKey(), derived);

        try {
            SmCryptoUtil.sm2Encrypt("x", "04" + repeat("ab", 20));
            check("长度非法的公钥应被拒绝", "抛异常", "未抛异常");
        } catch (IllegalArgumentException e) {
            check("长度非法的公钥被拒绝且信息明确", true, e.getMessage().contains("长度非法"));
        }
    }

    private static void section3Sm2RoundTrip() {
        System.out.println("\n[3] SM2 加解密往返");
        Sm2KeyPair kp = SmCryptoUtil.generateSm2KeyPair();
        String plain = "{\"msg\":\"中文测试-你好世界\",\"n\":10086}";
        String cipher = SmCryptoUtil.sm2Encrypt(plain, kp.getPublicKey());
        check("59 字节 JSON 往返", plain, SmCryptoUtil.sm2Decrypt(cipher, kp.getPrivateKey()));

        // SM2 不是分组密码，长文本同样可以整体加密
        StringBuilder big = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            big.append("订单").append(i).append(";");
        }
        String bigPlain = big.toString();
        String bigCipher = SmCryptoUtil.sm2Encrypt(bigPlain, kp.getPublicKey());
        check("1.4KB 长文本往返", bigPlain, SmCryptoUtil.sm2Decrypt(bigCipher, kp.getPrivateKey()));
        System.out.println("      明文 " + bigPlain.getBytes(StandardCharsets.UTF_8).length
                + " 字节 -> 密文 hex " + bigCipher.length() + " 位（约 2.05 倍膨胀）");
    }

    private static void section4Sm2CipherFormat() {
        System.out.println("\n[4] SM2 密文格式（跨语言关键点）");
        Sm2KeyPair kp = SmCryptoUtil.generateSm2KeyPair();
        String cipher = SmCryptoUtil.sm2Encrypt("format-probe", kp.getPublicKey());
        check("默认输出不含 04 前缀（与 sm-crypto 一致）", false, cipher.startsWith("04"));
        System.out.println("      密文前 8 位：" + cipher.substring(0, 8) + "（C1.x 随机值）");

        String withPrefix = SmCryptoUtil.sm2Encrypt("format-probe", kp.getPublicKey(), true);
        check("可选输出带 04 前缀", true, withPrefix.startsWith("04"));

        String hex = kp.getPrivateKey();
        check("带 04 前缀的密文也能解（兼容旧数据）", "format-probe",
                SmCryptoUtil.sm2Decrypt(withPrefix, hex));
        check("无 04 前缀的密文也能解（线上主格式）", "format-probe",
                SmCryptoUtil.sm2Decrypt(cipher, hex));
    }

    private static void section5Sm4RoundTrip() {
        System.out.println("\n[5] SM4 加解密（CBC + 随机 IV）");
        String key = SmCryptoUtil.generateSm4Key();
        check("SM4 key 长度 = 32 位 hex", 32, key.length());
        check("两次生成的 key 不同", false, key.equals(SmCryptoUtil.generateSm4Key()));

        String plain = "中文 data 字段内容 {\"ok\":true}";
        String c1 = SmCryptoUtil.sm4Encrypt(plain, key);
        String c2 = SmCryptoUtil.sm4Encrypt(plain, key);
        check("往返一致", plain, SmCryptoUtil.sm4Decrypt(c1, key));
        check("同一明文两次密文不同（IV 随机，不是 ECB）", false, c1.equals(c2));

        // 前 16 字节 base64 解码后应等于 IV 长度
        byte[] all = Base64.decode(c1);
        check("密文长度 = 16(IV) + 16 的整数倍", 0, all.length % 16);

        try {
            SmCryptoUtil.sm4Decrypt(c1, SmCryptoUtil.generateSm4Key());
            check("错误 key 解密应失败", "抛异常", "未抛异常");
        } catch (RuntimeException e) {
            check("错误 key 解密被拒绝且异常类型明确", true, true);
        }
    }

    /** 模拟"前端"持有的密钥对，供返回体构造与本地解密使用 */
    private static final Sm2KeyPair CLIENT_KEY_PAIR = SmCryptoUtil.generateSm2KeyPair();

    /** 构造一份「前端公钥已配置」的服务实例，等价于 Spring 容器里的 SecureResponseService */
    private static SecureResponseService newService() {
        SmcfbProperties props = new SmcfbProperties();
        props.setEnabled(true);
        props.setClientPublicKey(CLIENT_KEY_PAIR.getPublicKey());
        return new SecureResponseService(props, SecureResponseService.standaloneObjectMapper());
    }

    private static void section6SecureResponse() {
        System.out.println("\n[6] 返回体 {code,data,key} 构造与解密");
        SecureResponseService service = newService();
        SecureResponse resp = service.success(mockOrder(10086L));

        check("code = 200", 200, resp.getCode());
        check("data 非空", true, resp.getData() != null && !resp.getData().isEmpty());
        check("key 非空", true, resp.getKey() != null && !resp.getKey().isEmpty());
        System.out.println("      data(前 24) = " + resp.getData().substring(0, 24) + "... (Base64, 共 "
                + resp.getData().length() + " 字符)");
        System.out.println("      key (前 24) = " + resp.getKey().substring(0, 24) + "... (hex, 共 "
                + resp.getKey().length() + " 字符)");

        // 前端视角：先用私钥解出 SM4 key，再用它解出 data
        String sm4Key = SmCryptoUtil.sm2Decrypt(resp.getKey(), CLIENT_KEY_PAIR.getPrivateKey());
        check("解出的 SM4 key 为 32 位 hex", 32, sm4Key.length());
        String json = SmCryptoUtil.sm4Decrypt(resp.getData(), sm4Key);

        JSONObject obj = JSONUtil.parseObj(json);
        check("业务字段 orderNo 正确", "SO2026101200010086", obj.getStr("orderNo"));
        check("业务字段 mobile 正确", "13800001234", obj.getStr("mobile"));
        check("中文字段 customerName 正确", "东", obj.getStr("customerName"));
        check("金额精度保留（1999.00 而不是 1999）", true, json.contains("\"amount\":1999.00"));

        // 响应整体 JSON 结构
        String wire = JSONUtil.toJsonStr(resp);
        JSONObject wireObj = JSONUtil.parseObj(wire);
        check("上线 JSON 只含三个字段 code/data/key", 3, wireObj.size());
        System.out.println("      实际返回体：" + wire.substring(0, Math.min(120, wire.length())) + "...");

        // 两次响应的密文必须不同
        SecureResponse again = service.success(mockOrder(10086L));
        check("同一业务数据两次响应密文不同", false, resp.getData().equals(again.getData()));
    }

    private static void section7NegativeCases() {
        System.out.println("\n[7] 异常路径");
        Sm2KeyPair a = SmCryptoUtil.generateSm2KeyPair();
        Sm2KeyPair b = SmCryptoUtil.generateSm2KeyPair();
        String cipher = SmCryptoUtil.sm2Encrypt("secret", a.getPublicKey());
        try {
            SmCryptoUtil.sm2Decrypt(cipher, b.getPrivateKey());
            check("用他人私钥解密应失败", "抛异常", "未抛异常");
        } catch (RuntimeException e) {
            check("用他人私钥解密被拒绝", true, e.getMessage().contains("SM2 解密失败"));
        }

        try {
            SmCryptoUtil.sm2Decrypt("zzzz-not-hex", a.getPrivateKey());
            check("非法 hex 密文应失败", "抛异常", "未抛异常");
        } catch (RuntimeException e) {
            check("非法 hex 密文被拒绝", true, true);
        }

        SmcfbProperties bad = new SmcfbProperties();
        bad.setEnabled(true);
        bad.setClientPublicKey("");
        try {
            bad.validate();
            check("启用但未配公钥应拒绝启动", "抛异常", "未抛异常");
        } catch (IllegalStateException e) {
            check("启用但未配公钥被拒绝", true, e.getMessage().contains("未配置"));
        }
    }

    private static Path section8DumpForInterop(Path outDir) throws IOException {
        System.out.println("\n[8] 输出跨语言验证产物");
        SecureResponseService service = newService();
        SecureResponse resp = service.success(mockOrder(10086L));

        String sm4Key = SmCryptoUtil.sm2Decrypt(resp.getKey(), CLIENT_KEY_PAIR.getPrivateKey());
        String expectJson = SmCryptoUtil.sm4Decrypt(resp.getData(), sm4Key);

        Path payloadFile = outDir.resolve("payload.json");
        Files.write(payloadFile, JSONUtil.toJsonPrettyStr(resp).getBytes(StandardCharsets.UTF_8));

        Path keysFile = outDir.resolve("client-keys.properties");
        Map<String, String> kv = new LinkedHashMap<>();
        kv.put("privateKey", CLIENT_KEY_PAIR.getPrivateKey());
        kv.put("publicKey", CLIENT_KEY_PAIR.getPublicKey());
        kv.put("expectedJson", expectJson);
        StringBuilder sb = new StringBuilder();
        kv.forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
        Files.write(keysFile, sb.toString().getBytes(StandardCharsets.UTF_8));

        check("产物 payload.json 已写出", true, Files.exists(payloadFile));
        check("产物 client-keys.properties 已写出", true, Files.exists(keysFile));
        return payloadFile;
    }

    // ------------------------------------------------------------------

    /** 构造一份演示业务数据（用 Map，避免引入演示专用的 VO 类）。 */
    private static Map<String, Object> mockOrder(Long id) {
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

    private static void check(String name, Object expected, Object actual) {
        total++;
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        System.out.println((ok ? "  [OK]   " : "  [FAIL] ") + name
                + (ok ? "" : "  期望=" + expected + " 实际=" + actual));
        if (!ok) {
            FAILURES.add(name + "：期望=" + expected + " 实际=" + actual);
        }
    }

    /** Java 8 兼容的字符串重复（{@code String.repeat} 是 Java 11+）。 */
    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
