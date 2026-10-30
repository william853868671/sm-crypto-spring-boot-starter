# sm-crypto-spring-boot-starter

> 前后端接口国密（SM2 + SM4）返回体加密的 Spring Boot Starter。
> Backend responses become unreadable on the wire: the body is encrypted with a one-time SM4 key,
> and that key is encrypted with the **frontend's SM2 public key** — only the paired private key can recover it.
> Interoperates with the WeChat mini-program `sm-crypto` library out of the box.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Maven Central](https://img.shields.io/badge/maven%20central-pending-orange.svg)](#发布到-maven-central)

---

## 一、这是什么

后端返回给前端的数据，在网线上是**看不懂的**：

- 每次响应随机生成一把 **SM4** 密钥加密返回体；
- 这把 SM4 密钥再用**前端（小程序）的 SM2 公钥**加密；
- 只有持有配对私钥的前端能还原业务数据。

```
后端                                     前端（小程序）
  │                                          │
  │  1. 随机生成 SM4 key（每次请求都换）        │
  │  2. SM4 加密返回体 JSON                   │
  │  3. 用【前端 SM2 公钥】加密 SM4 key        │
  │                                          │
  │  ── {code, data, key} ──────────────────▶│
  │                                          │  4. 用【前端 SM2 私钥】解出 SM4 key
  │                                          │  5. 用 SM4 key 解出业务数据
```

**它能防的是"看懂"，不是"调用"**：抓包/中间人拿不到业务明文，但任何人都能用公开的前端公钥
构造合法请求。接口鉴权（登录 token、限流、风控、人机验证）是另一回事，加密不能替代鉴权。

## 二、特性

- 基于 **Hutool 5.8 + BouncyCastle**，Spring Boot 3.x 自动装配；`@RestController` 返回体**默认即加密**，无需任何注解；个别接口需要明文时用 `@SmCFBEncrypt(false)` 显式关闭。
- 被加密的响应会附带响应头 **`X-SmCFBEncrypt: true`**，前端据此判断是否需要走解密流程（未加密时不带该头）。
- 返回的密文格式与前端 `sm-crypto` **完全对齐**（SM2 去 `04` 前缀 = C1C3C2；SM4 用 CBC + 随机 IV），
  前端无需做任何格式转换。
- 用 **Jackson** 序列化（保留 `BigDecimal` 尾数与 ISO-8601 时间），避免金额被抹零。
- 核心工具类 `SmCryptoUtil` 与 Spring 解耦，非 Spring 项目也能直接用。
- 支持**双向加密**：请求头带 `X-SmCFBEncrypt: true` 时，后端用 `smcfb.server-private-key` 自动解密请求体（与响应加密完全对称），`@RequestBody` 收到的就是明文。
- 提供命令行密钥对生成工具 `GenKeyPairTool`（一次生成前端对 + 后端对两套密钥），以及 Java ↔ JS 双向互通自测。

## 三、快速开始

### 1. 引入依赖

**Maven**

```xml
<dependency>
    <groupId>io.github.william853868671</groupId>
    <artifactId>sm-crypto-spring-boot-starter</artifactId>
    <version>2.0.2</version>
</dependency>
```

**Gradle (Kotlin DSL)**

```kotlin
implementation("io.github.william853868671:sm-crypto-spring-boot-starter:2.0.2")
```

### 2. 生成密钥对

```bash
# 仓库根目录
./build.sh keys        # 生成两套密钥对并写入 ./keys

# 或不用 Maven：
java -cp target/classes:<依赖> \
  com.github.william853868671.smcrypto.tool.GenKeyPairTool --out ./keys
```

工具一次生成**两套**密钥对：

| 文件 | 内容 | 用途 |
|---|---|---|
| `keys/smcfb.yml.snippet` | 前端公钥 + 后端私钥 | 贴进后端 `application.yml` |
| `keys/smcfb-frontend.txt` | 前端私钥 + 后端公钥 | 前端持有（加密请求用后端公钥、解密响应用前端私钥） |

> **方向别搞反**：响应加密用「前端公钥」（后端配置）/「前端私钥」（前端持有）；请求解密用「后端私钥」（后端配置）/「后端公钥」（前端持有）。各方都用**对方的公钥**加密、用**自己的私钥**解密。

### 3. 配置

```yaml
smcfb:
  enabled: true                       # 响应体加密开关（默认 true）
  client-public-key: "04ff223d..."    # 前端 SM2 公钥（130 位 hex），用于加密响应
  server-private-key: "d4e5f6..."    # 后端 SM2 私钥（64 位 hex），用于解密请求
  request-decrypt-enabled: true       # 是否解密前端加密的请求体（默认 true）
  require-annotation: false           # 是否必须显式标 @SmCFBEncrypt 才加密（默认 false）
  exclude-paths:                      # 命中这些 Ant 路径的接口不加密、原样返回（可选）
    - /v3/api-docs/**
    - /swagger-ui/**
    - /error
    - /actuator/**
  fail-fast: true                     # 密钥格式不对直接拒绝启动
```

- `enabled: false` 时响应照常返回明文，方便联调对比。
- `request-decrypt-enabled: false` 时后端不再解密请求（响应加密仍按 `enabled` 进行），前端可发明文请求。
- `require-annotation: true` 时切换为「显式标注才加密」模式：只有标了 `@SmCFBEncrypt`（且值不为 `false`）的接口才加密，没标的接口一律明文。默认 `false`（返回体默认即加密）。
- `exclude-paths`（List，Ant 风格路径，如 `/v3/api-docs/**`、`/swagger-ui/**`、`/error`、`/actuator/**`）：命中的接口**整体跳过加密**，原样明文返回且不带 `X-SmCFBEncrypt` 头。典型用途是 Swagger/Knife4j 文档、健康检查、Actuator 这类「必须直连、不能加密」的端点。比逐个标 `@SmCFBEncrypt(false)` 省事，也比 `require-annotation=true` 轻（后者会把「默认即加密」整体反转）。路径按请求 URI 的 path 部分做 Ant 匹配（`**` 匹配多级）。
- 只配 `client-public-key` 也能启动：未配 `server-private-key` 时响应加密照常；只有当前端真的发来 `X-SmCFBEncrypt: true` 的请求时才会运行期报错提示补配私钥。

### 4. 返回体加密（默认即加密）

本 starter 对 `@RestController` 的返回体**默认全部加密**，大多数接口什么都不用标就能拿到加密返回体。
因此 `@SmCFBEncrypt` 注解的主要用途是「**显式关闭**」个别必须明文的接口（健康检查、回调、第三方对接等）。

```java
@RestController
public class OrderController {

    @GetMapping("/api/order/{id}")        // 默认加密：什么都不用标
    public OrderVO detail(@PathVariable Long id) {
        return orderService.find(id);
    }

    @SmCFBEncrypt(false)                  // 显式关闭：明文返回，不带 X-SmCFBEncrypt 头
    @GetMapping("/api/callback")
    public Object callback() {
        return rawPayload;
    }
}
```

加密规则：

- **不加注解 / `@SmCFBEncrypt(true)`（默认）** → 都按加密返回，响应头带 `X-SmCFBEncrypt: true`。
- **`@SmCFBEncrypt(false)`** → 不加密，按 Spring 默认方式原样序列化返回。

优先级与位置：

- 注解可标在**方法**或 **Controller 类**上（标在类上则类内所有接口沿用该值）。
- **方法级注解优先于类级**：类上标了 `@SmCFBEncrypt(false)`、某方法又标 `@SmCFBEncrypt(true)`，以方法级为准。

两种模式（`smcfb.require-annotation`）：

- **`false`（默认）— 默认即加密**：不加注解也加密；`@SmCFBEncrypt(false)` 才关掉。适合「绝大多数接口都要加密」。
- **`true` — 显式标注才加密**：只有标了 `@SmCFBEncrypt` 的接口才加密，没标的接口一律明文。适合「仅个别接口需要加密」。
  此模式下 `@SmCFBEncrypt` 注解的主要用途变成「开启」而非「关闭」。

**排除整类路径（如 Swagger）：** 如果想让某几类端点（Swagger 文档、健康检查、Actuator）不加密、其余保持默认加密，优先用 `smcfb.exclude-paths` 按路径排除（见上方配置），而不是给每个业务接口加注解。Swagger/Knife4j 是框架内部端点，没法用 `@SmCFBEncrypt` 标注，只能靠路径排除。例如：

```yaml
smcfb:
  exclude-paths:
    - /v3/api-docs/**
    - /swagger-ui/**
    - /doc.html
```

其它说明：

- `enabled: false`（见上节配置）时整套加密不生效，所有接口都明文返回，注解被忽略，方便联调对比。
- 加密后响应头会带 `X-SmCFBEncrypt: true`，前端可据此分支解密。
- **2.0.0 起已移除历史别名 `@EncryptedResponse`**，统一使用 `@SmCFBEncrypt`（从 1.0.x 升级时把 `@EncryptedResponse` 改成 `@SmCFBEncrypt` 即可，行为完全一致）。

不想要注解，也可以手动包：

```java
return secureResponseService.success(orderVO);   // 业务里自己包：返回 SecureResponse，Advice 会识别并补上 X-SmCFBEncrypt 头
```

### 5. 接收加密请求（请求解密）

前端把请求体用**后端公钥**加密后发出，并带请求头 `X-SmCFBEncrypt: true`，后端会自动解密再交给 `@RequestBody`——业务代码完全无感，就像收明文一样：

```js
// 前端：用后端公钥加密请求体（完整脚本见 tools/interop/encrypt-http-request.js）
const body = encryptRequest(plainJson, SERVER_PUBLIC_KEY);
wx.request({ url, method: 'POST', data: body, header: { 'X-SmCFBEncrypt': 'true' } });
```

```java
@PostMapping("/api/order")
public OrderVO create(@RequestBody OrderVO vo) {   // vo 已是解密后的明文
    return orderService.create(vo);
}
```

- 解密只在请求头确为 `true` 且配了 `server-private-key` 时发生；普通明文请求（不带头）原样放行。
- 请求体密文结构与响应一致：`{ "data": "Base64(IV‖SM4密文)", "key": "SM4密钥的SM2密文" }`，见下节。

### 6. 启动验证

```bash
mvn spring-boot:run        # 在 samples/demo 下，或你自己的应用
curl http://127.0.0.1:8080/api/plain/order/5   # 对照：明文
curl http://127.0.0.1:8080/api/order/5         # 加密：data/key 都是密文
```

## 四、接口格式

```json
{
  "code": 200,
  "data": "2LO2PRaIY3Mx6GoFJwHThk0cjQtGZrV63KDHQMPxggb6esikwIZb5dEIimnc...",
  "key":  "1E7C3679C2AC247F65292AD836EDE088A5FA61B3109B24A61E0DAC5F6280..."
}
```

| 字段 | 内容 | 编码 |
|---|---|---|
| `code` | 业务状态码 | 明文 |
| `data` | 业务数据的 SM4 密文 | `Base64( IV(16字节) ‖ 密文 )` |
| `key` | SM4 密钥的 SM2 密文 | hex，**无 04 前缀** |

`data` 内含 IV：SM4-CBC 需要随机初始向量；为保持 `{code,data,key}` 三字段结构不变，IV 前置到密文里一起传
（IV 不是秘密，但同一密钥下绝不可复用）。

**响应头**

| Header | 取值 | 含义 |
|---|---|---|
| `X-SmCFBEncrypt` | `true` | 本响应体已加密（`{code,data,key}`）；前端据此走解密。未加密时不带此头。 |

**请求加密（可选，与响应对称）**

当前端需要上传加密请求体时，用【后端公钥】加密，并把同一个 `X-SmCFBEncrypt: true` 放在**请求头**：

| Header | 取值 | 含义 |
|---|---|---|
| `X-SmCFBEncrypt` | `true` | 本请求体已加密；后端据此自动解密后再交给 `@RequestBody`。 |

请求体密文结构与响应完全相同：

```json
{ "data": "Base64(IV‖SM4-CBC密文)", "key": "SM4密钥的SM2密文(hex,无04前缀)" }
```

解密步骤：用 `server-private-key` 解出 SM4 密钥 → 用该密钥 SM4 解密 `data`。`code` 字段在请求体里可省略。

## 五、微信小程序端解密

```js
// npm i sm-crypto
const sm2 = require('sm-crypto').sm2;
const sm4 = require('sm-crypto').sm4;

// 私钥保存在本地存储，不要写死在源码里
const PRIVATE_KEY = wx.getStorageSync('sm2_private_key');

function decryptResponse(res) {
  const { code, data, key } = res.data;

  // 1. 用私钥解出 SM4 密钥
  const sm4Key = sm2.doDecrypt(key, PRIVATE_KEY, 1);   // 1 = C1C3C2 模式

  // 2. 拆出 IV 与密文
  const raw = wx.base64ToArrayBuffer(data);
  const all = new Uint8Array(raw);
  const iv = all.slice(0, 16);
  const cipher = all.slice(16);

  // 3. SM4-CBC 解密
  const plain = sm4.decrypt(
    Array.from(cipher), sm4Key,
    { mode: 'cbc', iv: Array.from(iv), output: 'string' }
  );

  return { code, data: JSON.parse(plain) };
}
```

`sm2.doDecrypt` 的第三个参数 `1` 表示 C1C3C2 排列。后端输出已和它对齐，前端**不需要**任何格式转换。

### 小程序端加密请求

```js
// npm i sm-crypto
const sm2 = require('sm-crypto').sm2;
const sm4 = require('sm-crypto').sm4;
const crypto = require('crypto');

// SERVER_PUBLIC_KEY 来自 keys/smcfb-frontend.txt 里的 server-public-key，存本地
function encryptRequest(plainJson, SERVER_PUBLIC_KEY) {
  const sm4Key = crypto.randomBytes(16).toString('hex');     // 32 hex（16 字节）
  const iv = crypto.randomBytes(16);
  const cipherHex = sm4.encrypt(plainJson, sm4Key, { mode: 'cbc', iv: iv.toString('hex'), output: 'hex' });
  const data = Buffer.concat([iv, Buffer.from(cipherHex, 'hex')]).toString('base64');
  const key = sm2.doEncrypt(sm4Key, SERVER_PUBLIC_KEY, 1);    // 1 = C1C3C2，与后端对齐
  return { data, key };
}

// 发送时带请求头 X-SmCFBEncrypt: true
wx.request({ url: '/api/order', method: 'POST',
  data: encryptRequest(JSON.stringify(vo), SERVER_PUBLIC_KEY),
  header: { 'X-SmCFBEncrypt': 'true' } });
```

后端收到后会自动解密。完整可运行脚本见 `tools/interop/encrypt-http-request.js`。

## 六、三个容易踩的坑（已在代码里处理）

1. **SM2 密文的 `04` 前缀**：Hutool/BC 输出 `04‖C1‖C3‖C2`，sm-crypto 期望 `C1‖C3‖C2`。出口统一去 `04`，入口两种都兼容。
2. **SM4 默认 ECB**：`SmUtil.sm4(key)` 默认 `SM4/ECB`，相同明文块产生相同密文块，可被模式分析。本工具类一律用 **CBC + 随机 IV**。
3. **金额尾数被抹**：Hutool `JSONUtil` 会把 `BigDecimal("1999.00")` 序列化成 `1999`。本模块改用 **Jackson**，保留 `1999.00`。

## 七、生产上线前必读

1. **这套机制防"看懂"，不防"调用"。** 限制"谁能调"需要登录 token + 限流 + 风控 + 人机验证。
2. **私钥保管是单点。** 前端私钥一旦泄露（源码泄露、被反编译、本地存储被读），全部返回数据可被解开。建议每台设备首次启动本地生成密钥对，只把公钥上报后端；私钥存 `wx.setStorageSync` 并考虑加密存储。
3. **HTTPS 仍是前提。** 明文 HTTP 下，公钥本身可被中间人替换成攻击者的公钥，整条链路失效。
4. **性能。** SM2 解密毫秒级、SM4 微秒级；超高 QPS（上万）应改为"握手协商一次会话密钥，后续只用 SM4"，`SmCryptoUtil` 可直接复用为其中的 SM4 部分。
5. **多端密钥。** 当前 `client-public-key` 是单值；多端时改成"按 appId / 设备号查表取公钥"即可，工具类本身不用改。

## 八、构建与测试

```bash
# 编译 + 跑纯 Java 自测 + MockMvc 集成测试（含 X-SmCFBEncrypt 头验证）
mvn clean test

# 或不用 Maven：
./build.sh all

# 双向跨语言互通（需先 npm i sm-crypto，再 export NODE_PATH=<node_modules>）
./build.sh interop
```

自测覆盖：密钥格式、SM2/SM4 往返、长文本、密文格式、异常路径、返回体构造、Java(Hutool) ↔ JS(sm-crypto) 双向互通，
以及 `@SmCFBEncrypt` 触发加密并写入 `X-SmCFBEncrypt: true` 响应头（未加密接口不带该头）、
请求头带 `X-SmCFBEncrypt: true` 时后端自动解密请求体并由 Controller 收到明文。

## 九、目录结构

```
sm-crypto-spring-boot-starter/
├── pom.xml                 库工程（发布到 Maven Central 的配置已就绪）
├── build.sh                无 Maven 时的编译/自测脚本
├── src/
│   ├── main/java/com/github/william853868671/smcrypto/
│   │   ├── crypto/         SmCryptoUtil / Sm2KeyPair / SecureResponse（与 Spring 解耦）
│   │   ├── spring/         SmcfbProperties / SecureResponseService /
│   │   │                   SmCFBEncrypt / SecureResponseAdvice /
│   │   │                   SmcfbDecryptAdvice（请求体解密）/ SmCryptoAutoConfiguration（自动配置）
│   │   └── tool/           GenKeyPairTool（命令行生成前端对 + 后端对两套密钥）
│   └── test/               SecurePayloadSelfTest / InteropPeerCheck / JUnit 包装
│       └── it/             SmCFBEncryptAdviceTest（MockMvc 验证响应加密头 + 请求解密）
├── samples/demo/           可运行的演示 Spring Boot 应用（引用本 starter）
└── tools/interop/          小程序端解密/加密/互通验证脚本（decrypt-http-response.js / encrypt-http-request.js / verify-interop.js）
```

## 十、License

[Apache License 2.0](LICENSE)。

---

## 发布到 Maven Central

`pom.xml` 已配好发布所需插件：`maven-source-plugin`、`maven-javadoc-plugin`、`maven-gpg-plugin`
与 `central-publishing-maven-plugin`（Central Portal）。发布前需：

1. 在 [Central Portal](https://central.sonatype.com/) 注册命名空间 `io.github.william853868671`；
2. 配置 GPG 签名密钥（`~/.m2/settings.xml` 的 `gpg-signing` server）；
3. 在 `~/.m2/settings.xml` 配置 `central` server 的 token；
4. `mvn clean deploy` 即可。
   或发布到 GitHub Packages：`mvn clean deploy -DskipStaging`（已配 `distributionManagement`）。
