package com.github.william853868671.smcrypto.crypto;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.RandomUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.CryptoException;
import cn.hutool.crypto.Mode;
import cn.hutool.crypto.Padding;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SM4;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 国密加解密工具类（基于 Hutool 5.8 + BouncyCastle）。
 *
 * <h3>对外统一的密钥与密文格式</h3>
 * <pre>
 *   SM2 私钥      : 64  位 hex（32 字节标量），例：a1b2...（长度 64）
 *   SM2 公钥      : 130 位 hex（04 ‖ X ‖ Y，非压缩点），例：04a1b2...（长度 130）
 *   SM2 密文      : 无 04 前缀的 C1C3C2 hex —— 与前端 sm-crypto 的
 *                   sm2.doEncrypt(msg, publicKey, 1) / sm2.doDecrypt(cipher, sk, 1)
 *                   完全一致，前端无需做任何格式适配。
 *   SM4 密钥      : 32 位 hex（16 字节）
 *   SM4 密文      : Base64( IV(16字节) ‖ 密文 )，即 IV 前置随密文一起传输
 * </pre>
 *
 * <h3>为什么 SM2 密文要去掉 04 前缀</h3>
 * Hutool 的 {@code encryptBcd()} 与 BC 原生输出一样，是「04 ‖ C1 ‖ C3 ‖ C2」；
 * 而 sm-crypto 的 {@code doEncrypt()} 输出「C1 ‖ C3 ‖ C2」，没有开头的 04。
 * 两边不统一就会出现「Java 能自解、前端解不开」这类最难查的故障。
 * 本工具类选择以 sm-crypto（前端）为准，出口去掉 04，入口自动兼容两种。
 *
 * <h3>为什么 SM4 用 CBC 而不是默认的 ECB</h3>
 * Hutool 的 {@code SmUtil.sm4(key)} 默认是 SM4/ECB/PKCS5Padding，相同的明文块
 * 会得到相同的密文块，可直接被模式分析攻击还原结构。因此这里一律使用
 * CBC + 随机 IV；每次加密重新生成 IV 并随密文一起返回（IV 不是秘密，但绝不能复用）。
 *
 * @author william
 */
public final class SmCryptoUtil {

    private SmCryptoUtil() {
    }

    /** SM2 私钥 hex 长度（32 字节 = 64 hex） */
    public static final int SM2_PRIVATE_KEY_HEX_LENGTH = 64;
    /** SM2 公钥 hex 长度（04 ‖ X ‖ Y = 65 字节 = 130 hex） */
    public static final int SM2_PUBLIC_KEY_HEX_LENGTH = 130;
    /** SM4 密钥字节数 */
    public static final int SM4_KEY_BYTES = 16;
    /** SM4 IV 字节数 */
    public static final int SM4_IV_BYTES = 16;

    /** SM2 非压缩点前缀 */
    private static final String POINT_PREFIX = "04";

    // ==================================================================
    // SM2
    // ==================================================================

    /**
     * 生成 SM2 密钥对（hex 裸格式）。
     *
     * <p>私钥必须只留在需要"解密"或"签名"的一方：本方案中后端返回数据加密时，
     * 用【前端的公钥】加密 SM4 密钥，私钥由前端持有；千万不要把私钥下发给前端之外的人。</p>
     *
     * @return 密钥对，publicKey 为 130 位 hex，privateKey 为 64 位 hex
     */
    public static Sm2KeyPair generateSm2KeyPair() {
        SM2 sm2 = SmUtil.sm2();
        String privateKeyHex = sm2.getDHex();
        String publicKeyHex = HexUtil.encodeHexStr(sm2.getQ(false));
        return new Sm2KeyPair(publicKeyHex, privateKeyHex);
    }

    /**
     * SM2 加密（公钥加密）。
     *
     * @param plainText    明文
     * @param publicKeyHex 130 位 hex 公钥（04 开头）
     * @return 密文，无 04 前缀的 C1C3C2 hex，可直接交前端 sm-crypto 解密
     */
    public static String sm2Encrypt(String plainText, String publicKeyHex) {
        return sm2Encrypt(plainText, publicKeyHex, false);
    }

    /**
     * SM2 加密。
     *
     * @param withPointPrefix 是否保留 04 前缀。与前端 sm-crypto 对接时传 false（默认）；
     *                        只与 Java 端自身交互时可传 true
     */
    public static String sm2Encrypt(String plainText, String publicKeyHex, boolean withPointPrefix) {
        if (StrUtil.isBlank(plainText)) {
            throw new IllegalArgumentException("SM2 加密明文不能为空");
        }
        String pk = requirePublicKey(publicKeyHex);
        // 只带公钥构造，私钥为 null：这样即使调用方拿了私钥也无法在此处"解密"
        SM2 sm2 = new SM2(null, pk);
        String cipherHex = sm2.encryptBcd(plainText, KeyType.PublicKey);
        return withPointPrefix ? cipherHex : stripPointPrefix(cipherHex);
    }

    /**
     * SM2 解密（私钥解密）。
     *
     * @param cipherHex    密文 hex，兼容「无 04 前缀」（sm-crypto 输出）与「带 04 前缀」（Hutool/BC 输出）两种
     * @param privateKeyHex 64 位 hex 私钥
     * @return 明文
     * @throws CryptoException 密文格式错误或私钥不匹配时抛出
     */
    public static String sm2Decrypt(String cipherHex, String privateKeyHex) {
        if (StrUtil.isBlank(cipherHex)) {
            throw new IllegalArgumentException("SM2 待解密密文不能为空");
        }
        if (StrUtil.isBlank(privateKeyHex)) {
            throw new IllegalArgumentException("SM2 私钥不能为空");
        }
        String hex = cleanHex(cipherHex);
        SM2 sm2 = new SM2(privateKeyHex, null);

        // 先按「无 04 前缀」解（线上统一格式，命中率 100%）；失败再按「带 04 前缀」解
        try {
            return sm2.decryptStrFromBcd(POINT_PREFIX + hex, KeyType.PrivateKey);
        } catch (RuntimeException firstTry) {
            if (hex.startsWith(POINT_PREFIX) && hex.length() > SM2_PRIVATE_KEY_HEX_LENGTH) {
                try {
                    return sm2.decryptStrFromBcd(hex, KeyType.PrivateKey);
                } catch (RuntimeException ignored) {
                    // 落到下面统一抛出，保留首次异常信息
                }
            }
            throw new CryptoException("SM2 解密失败：请检查密文是否为 C1C3C2 格式、私钥是否与加密所用公钥配对", firstTry);
        }
    }

    /**
     * 从私钥推导公钥（hex 裸格式）。用于仅保存了私钥、需要重建公钥的场景。
     *
     * <p>推导公式：{@code Q = d · G}，直接在 SM2 推荐曲线上做点乘。
     * 注意不能用 {@code SM2.getQ()} —— 只传私钥构造的 SM2 实例内部没有公钥参数，会 NPE。</p>
     *
     * @param privateKeyHex 64 位 hex 私钥
     * @return 130 位 hex 公钥
     */
    public static String derivePublicKey(String privateKeyHex) {
        String sk = cleanHex(privateKeyHex);
        if (sk.length() != SM2_PRIVATE_KEY_HEX_LENGTH) {
            throw new IllegalArgumentException(
                    "SM2 私钥长度非法：期望 " + SM2_PRIVATE_KEY_HEX_LENGTH + " 位 hex，实际 " + sk.length() + " 位");
        }
        ECPoint q = SmUtil.SM2_DOMAIN_PARAMS.getG()
                .multiply(new BigInteger(sk, 16))
                .normalize();
        return HexUtil.encodeHexStr(q.getEncoded(false));
    }

    // ==================================================================
    // SM4
    // ==================================================================

    /**
     * 生成一个随机 SM4 密钥。
     *
     * @return 32 位 hex 密钥（16 字节）
     */
    public static String generateSm4Key() {
        return HexUtil.encodeHexStr(randomSm4KeyBytes());
    }

    /**
     * 生成随机 SM4 密钥字节。
     */
    public static byte[] randomSm4KeyBytes() {
        // RandomUtil.randomBytes 底层取 SecureRandom，可安全用于密钥生成
        return RandomUtil.randomBytes(SM4_KEY_BYTES);
    }

    /**
     * SM4 加密（CBC / PKCS5Padding / 随机 IV）。
     *
     * <p>返回值为 {@code Base64(IV ‖ 密文)}，前 16 字节是 IV，其余是密文。
     * 前端解密时先取前 16 字节作为 IV，再用同一 key 做 CBC 解密。</p>
     *
     * @param plainText 明文
     * @param keyHex    32 位 hex 密钥
     * @return Base64 串
     */
    public static String sm4Encrypt(String plainText, String keyHex) {
        if (plainText == null) {
            throw new IllegalArgumentException("SM4 加密明文不能为 null");
        }
        byte[] iv = RandomUtil.randomBytes(SM4_IV_BYTES);
        return sm4EncryptWithIv(plainText, keyHex, HexUtil.encodeHexStr(iv));
    }

    /**
     * SM4 加密（指定 IV）。一般业务请用 {@link #sm4Encrypt(String, String)}，此方法主要用于自测与联调复现问题。
     *
     * @param ivHex 32 位 hex IV，**同一 key 下绝不可复用**
     */
    public static String sm4EncryptWithIv(String plainText, String keyHex, String ivHex) {
        byte[] key = requireSm4Key(keyHex);
        byte[] iv = requireIv(ivHex);
        SM4 sm4 = new SM4(Mode.CBC, Padding.PKCS5Padding, key, iv);
        byte[] cipher = sm4.encrypt(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.encode(ArrayUtil.addAll(iv, cipher));
    }

    /**
     * SM4 解密。
     *
     * @param payloadBase64 {@code Base64(IV ‖ 密文)}，即 {@link #sm4Encrypt} 的返回值
     * @param keyHex        与加密时相同的 32 位 hex 密钥
     * @return 明文
     */
    public static String sm4Decrypt(String payloadBase64, String keyHex) {
        if (StrUtil.isBlank(payloadBase64)) {
            throw new IllegalArgumentException("SM4 待解密内容不能为空");
        }
        byte[] key = requireSm4Key(keyHex);
        byte[] all;
        try {
            all = Base64.decode(payloadBase64);
        } catch (RuntimeException e) {
            throw new CryptoException("SM4 密文不是合法的 Base64", e);
        }
        if (all.length <= SM4_IV_BYTES) {
            throw new CryptoException("SM4 密文长度不足，至少应包含 " + SM4_IV_BYTES + " 字节 IV 和 1 字节密文");
        }
        byte[] iv = Arrays.copyOfRange(all, 0, SM4_IV_BYTES);
        byte[] cipher = Arrays.copyOfRange(all, SM4_IV_BYTES, all.length);
        SM4 sm4 = new SM4(Mode.CBC, Padding.PKCS5Padding, key, iv);
        return sm4.decryptStr(cipher, StandardCharsets.UTF_8);
    }

    /**
     * SM4 加解密往返自检，用于服务健康检查或配置校验。
     */
    public static boolean selfCheck() {
        try {
            Sm2KeyPair kp = generateSm2KeyPair();
            if (kp.getPublicKey().length() != SM2_PUBLIC_KEY_HEX_LENGTH
                    || kp.getPrivateKey().length() != SM2_PRIVATE_KEY_HEX_LENGTH) {
                return false;
            }
            String probe = "sm-self-check-自检-2026";
            if (!probe.equals(sm2Decrypt(sm2Encrypt(probe, kp.getPublicKey()), kp.getPrivateKey()))) {
                return false;
            }
            String key = generateSm4Key();
            if (!probe.equals(sm4Decrypt(sm4Encrypt(probe, key), key))) {
                return false;
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ==================================================================
    // 内部方法
    // ==================================================================

    private static String requirePublicKey(String publicKeyHex) {
        String pk = cleanHex(publicKeyHex);
        // 允许传入不带 04 的 128 位点坐标，这里统一补全
        if (pk.length() == SM2_PUBLIC_KEY_HEX_LENGTH - 2) {
            pk = POINT_PREFIX + pk;
        }
        if (pk.length() != SM2_PUBLIC_KEY_HEX_LENGTH) {
            throw new IllegalArgumentException(
                    "SM2 公钥长度非法：期望 " + SM2_PUBLIC_KEY_HEX_LENGTH + " 位 hex（04 开头），实际 " + pk.length() + " 位");
        }
        if (!pk.startsWith(POINT_PREFIX)) {
            throw new IllegalArgumentException("SM2 公钥必须以 04 开头（非压缩点格式）");
        }
        return pk;
    }

    private static byte[] requireSm4Key(String keyHex) {
        String k = cleanHex(keyHex);
        if (k.length() != SM4_KEY_BYTES * 2) {
            throw new IllegalArgumentException("SM4 密钥长度非法：期望 " + (SM4_KEY_BYTES * 2) + " 位 hex（16 字节），实际 " + k.length() + " 位");
        }
        return HexUtil.decodeHex(k);
    }

    private static byte[] requireIv(String ivHex) {
        String v = cleanHex(ivHex);
        if (v.length() != SM4_IV_BYTES * 2) {
            throw new IllegalArgumentException("SM4 IV 长度非法：期望 " + (SM4_IV_BYTES * 2) + " 位 hex，实际 " + v.length() + " 位");
        }
        return HexUtil.decodeHex(v);
    }

    private static String cleanHex(String hex) {
        return StrUtil.trimToEmpty(hex).toLowerCase().replace(" ", "").replaceAll("\\s", "");
    }

    private static String stripPointPrefix(String cipherHex) {
        return cipherHex.startsWith(POINT_PREFIX) ? cipherHex.substring(POINT_PREFIX.length()) : cipherHex;
    }
}
