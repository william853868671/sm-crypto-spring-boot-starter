# sm-crypto-spring-boot-starter-boot2

前后端国密（**SM2 + SM4**）返回体加密的 Spring Boot Starter，面向 **Spring Boot 2.7.x + Java 8**。

> 这是主线的兼容分支：功能、配置（`smcfb.*`）、注解（`@SmCFBEncrypt`）、响应头（`X-SmCFBEncrypt: true`）与
> [`sm-crypto-spring-boot-starter`](https://github.com/william853868671/sm-crypto-spring-boot-starter)（Spring Boot 3.x / Java 17）
> **完全一致**，只是依赖与字节码目标不同。新项目若用 Spring Boot 3.x，请直接用主线 starter。

## 兼容矩阵

| 维度 | 本模块（boot2） | 主线 starter |
|------|----------------|--------------|
| Spring Boot | **2.7.x**（Spring 5.3） | 3.x（Spring 6） |
| Java | **8** | 17 |
| Servlet API | javax.servlet（4.0） | jakarta.servlet（6.0） |
| 自动配置注册 | `META-INF/spring/...AutoConfiguration.imports` | 同左 |

> 注：本模块基于 `@AutoConfiguration`（Spring Boot 2.7 引入），因此**仅支持 Spring Boot 2.7 及以上**；
> 2.6 及更早版本无此注解，无法使用本模块（请升级到 2.7，或自行 backport）。

## 引入依赖

### Maven

```xml
<dependency>
    <groupId>io.github.william853868671</groupId>
    <artifactId>sm-crypto-spring-boot-starter-boot2</artifactId>
    <version>2.0.2</version>
</dependency>
```

### Gradle

```groovy
implementation("io.github.william853868671:sm-crypto-spring-boot-starter-boot2:2.0.2")
```

## 用法（与主线完全一致）

1. 生成两套密钥对（前端对 + 后端对）：
   ```bash
   ./build.sh keys        # 写入 ./keys：后端 application.yml 片段 + 前端持有文件
   ```
2. 在 `application.yml` 配置（默认返回体即加密）：
   ```yaml
smcfb:
  enabled: true
  client-public-key: "04ff223d..."     # 前端 SM2 公钥，用于加密响应
  server-private-key: "d4e5f6..."      # 后端 SM2 私钥，用于解密请求
  request-decrypt-enabled: true
  fail-fast: true
  exclude-paths:                       # 命中这些 Ant 路径的接口不加密、原样返回（可选）
    - /v3/api-docs/**
    - /swagger-ui/**
    - /error
    - /actuator/**
```
3. 个别接口需要明文时显式关闭：
   ```java
   @SmCFBEncrypt(false)
   @GetMapping("/health")
   public Map<String,Object> health() { ... }
   ```
   - `smcfb.require-annotation: true` 可切到「只有标了 `@SmCFBEncrypt` 才加密」的 opt-in 模式。
   - `smcfb.exclude-paths`（Ant 路径 List）可让 Swagger/Knife4j（`/v3/api-docs/**`、`/swagger-ui/**`）、`/error`、Actuator 等端点整体跳过加密——框架内部端点没法用注解标注，只能靠路径排除。

其余说明（加密机制、跨语言互通、双向解密、发布）见主线 starter 的 README。

## 本地构建与验证

```bash
mvn clean install -Dgpg.skip=true   # 编译（release 8）+ 跑测试（自测套件 + MockMvc 集成测试）
./build.sh keys                     # 生成密钥对
```

发布到 Maven Central：`mvn clean deploy`，再到 Central Portal 对该 deployment 点 Publish。
