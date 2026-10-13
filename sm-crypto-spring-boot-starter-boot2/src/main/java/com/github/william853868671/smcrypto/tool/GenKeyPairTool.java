package com.github.william853868671.smcrypto.tool;

import com.github.william853868671.smcrypto.crypto.Sm2KeyPair;
import com.github.william853868671.smcrypto.crypto.SmCryptoUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 密钥对生成工具（命令行运行，不依赖 Spring 容器）。
 *
 * <pre>
 *   # 仅打印
 *   java -cp target/classes:&lt;依赖&gt; com.github.william853868671.smcrypto.tool.GenKeyPairTool
 *
 *   # 同时写入文件
 *   java -cp target/classes:&lt;依赖&gt; com.github.william853868671.smcrypto.tool.GenKeyPairTool --out ./keys
 * </pre>
 *
 * <h3>本工具一次生成两套密钥对</h3>
 * <ul>
 *   <li><b>前端密钥对</b>：前端公钥给【后端配置】（smcfb.client-public-key，用于加密响应）；
 *       前端私钥由前端持有（解密响应）。</li>
 *   <li><b>后端密钥对</b>：后端私钥给【后端配置】（smcfb.server-private-key，用于解密请求）；
 *       后端公钥由前端持有（加密请求体）。</li>
 * </ul>
 *
 * <p>这样响应加密与请求解密就完全对称：各方都用「对方的公钥」加密、用「自己的私钥」解密。</p>
 */
public final class GenKeyPairTool {

    private GenKeyPairTool() {
    }

    public static void main(String[] args) throws IOException {
        Path outDir = null;
        for (int i = 0; i < args.length - 1; i++) {
            if ("--out".equals(args[i])) {
                outDir = Paths.get(args[i + 1]);
            }
        }

        // 前端密钥对：前端公钥 → 后端配置；前端私钥 → 前端持有
        Sm2KeyPair frontend = SmCryptoUtil.generateSm2KeyPair();
        // 后端密钥对：后端私钥 → 后端配置；后端公钥 → 前端持有（用于加密请求）
        Sm2KeyPair backend = SmCryptoUtil.generateSm2KeyPair();

        System.out.println("======================================================================");
        System.out.println(" SM2 密钥对已生成（前端对 + 后端对）");
        System.out.println("======================================================================");
        System.out.println();
        System.out.println("[前端持有 · 严格保密] 前端私钥 privateKey（解密响应用）：");
        System.out.println(frontend.getPrivateKey());
        System.out.println();
        System.out.println("[前端持有 · 用于加密请求] 后端公钥 publicKey（加密请求体用）：");
        System.out.println(backend.getPublicKey());
        System.out.println();
        System.out.println("[后端配置 · 可公开] 前端公钥 publicKey（填入 smcfb.client-public-key）：");
        System.out.println(frontend.getPublicKey());
        System.out.println();
        System.out.println("[后端配置 · 严格保密] 后端私钥 privateKey（填入 smcfb.server-private-key）：");
        System.out.println(backend.getPrivateKey());
        System.out.println();
        System.out.println("----------------------------------------------------------------------");
        System.out.println(" 提醒：私钥一旦泄露，任何人都能解开你与前端之间的全部数据；");
        System.out.println("       私钥不要写进前端源码仓库或打包进小程序产物，应保存在");
        System.out.println("       设备本地存储 / 安全模块中，并支持丢失后重新下发。");
        System.out.println("----------------------------------------------------------------------");

        if (outDir != null) {
            Files.createDirectories(outDir);
            Path backendSnippet = outDir.resolve("smcfb.yml.snippet");
            Path frontendFile = outDir.resolve("smcfb-frontend.txt");
            Files.write(backendSnippet, ("smcfb:\n"
                    + "  enabled: true\n"
                    + "  client-public-key: " + frontend.getPublicKey() + "\n"
                    + "  server-private-key: " + backend.getPrivateKey() + "\n"
                    + "  request-decrypt-enabled: true\n")
                    .getBytes(StandardCharsets.UTF_8));
            Files.write(frontendFile, ("# 前端持有（请勿提交到 git）\n"
                    + "client-private-key: " + frontend.getPrivateKey() + "\n"
                    + "server-public-key: " + backend.getPublicKey() + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            System.out.println();
            System.out.println("已写入目录 " + outDir.toAbsolutePath() + "：");
            System.out.println("  smcfb.yml.snippet     -> 后端 application.yml 片段（前端公钥 + 后端私钥）");
            System.out.println("  smcfb-frontend.txt    -> 前端持有（前端私钥 + 后端公钥），请自行加密保管");
        }
    }
}
