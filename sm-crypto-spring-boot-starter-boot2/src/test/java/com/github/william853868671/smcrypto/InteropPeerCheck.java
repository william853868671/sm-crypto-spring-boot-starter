package com.github.william853868671.smcrypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.HexUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * 跨语言互通验证 · Java 侧。
 *
 * <p>消费 JS 端（sm-crypto）产出的 {@code peer-from-js.json}，验证：
 * 后端能用私钥解开小程序加密的数据、能用 SM4 解出小程序加密的内容。</p>
 *
 * <pre>
 *   node tools/interop/verify-interop.js build/selftest    # 先生成 JS 产物
 *   java -cp build/classes:&lt;deps&gt; com.github.william853868671.smcrypto.InteropPeerCheck build/selftest
 * </pre>
 */
public class InteropPeerCheck {

    private static final List<String> FAILURES = new ArrayList<>();
    private static int total = 0;

    public static void main(String[] args) throws IOException {
        Path dir = Paths.get(args.length > 0 ? args[0] : "build/selftest");

        System.out.println("=========== Java 端解密小程序（sm-crypto）产物 ===========\n");

        String keysText = new String(Files.readAllBytes(dir.resolve("client-keys.properties")), StandardCharsets.UTF_8);
        String privateKey = kv(keysText, "privateKey");

        JSONObject peer = JSONUtil.parseObj(
                new String(Files.readAllBytes(dir.resolve("peer-from-js.json")), StandardCharsets.UTF_8));

        System.out.println("[1] SM2：小程序加密 → 后端私钥解密");
        String sm2Plain = SmCryptoUtil.sm2Decrypt(peer.getStr("sm2Cipher"), privateKey);
        check("SM2 解出的明文一致（含中文）", peer.getStr("plain"), sm2Plain);

        System.out.println("\n[2] SM4：小程序加密 → 后端解密");
        String sm4Plain = SmCryptoUtil.sm4Decrypt(
                buildIvPrefixedPayload(peer.getStr("sm4Iv"), peer.getStr("sm4Cipher")),
                peer.getStr("sm4Key"));
        check("SM4 解出的明文一致（含中文）", peer.getStr("plain"), sm4Plain);

        System.out.println("\n[3] 后端 SM2 加密 → Java 回读（自洽性）");
        String backCipher = SmCryptoUtil.sm2Encrypt("后端回话", SmCryptoUtil.derivePublicKey(privateKey));
        check("往返一致", "后端回话", SmCryptoUtil.sm2Decrypt(backCipher, privateKey));

        System.out.println("\n=========== 结果 ===========");
        System.out.println("通过 " + (total - FAILURES.size()) + " / " + total);
        if (FAILURES.isEmpty()) {
            System.out.println(">>> 全部通过：Java(Hutool) 与 JS(sm-crypto) 双向国密互通 OK");
        } else {
            System.out.println(">>> 失败项：");
            FAILURES.forEach(f -> System.out.println("    - " + f));
            System.exit(1);
        }
    }

    /**
     * 把 JS 端分别给出的 iv 与密文，拼成后端约定的 {@code Base64(IV ‖ 密文)} 结构。
     * 小程序端实际开发中建议直接拼接后 Base64 传输，这里为了直观断言而分开存放。
     */
    private static String buildIvPrefixedPayload(String ivHex, String cipherHex) {
        byte[] all = new byte[HexUtil.decodeHex(ivHex).length + HexUtil.decodeHex(cipherHex).length];
        byte[] iv = HexUtil.decodeHex(ivHex);
        byte[] cipher = HexUtil.decodeHex(cipherHex);
        System.arraycopy(iv, 0, all, 0, iv.length);
        System.arraycopy(cipher, 0, all, iv.length, cipher.length);
        return Base64.encode(all);
    }

    private static String kv(String text, String key) {
        for (String line : text.split("\n")) {
            int i = line.indexOf('=');
            if (i > 0 && key.equals(line.substring(0, i).trim())) {
                return line.substring(i + 1).trim();
            }
        }
        throw new IllegalArgumentException("未找到配置项 " + key);
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
}
