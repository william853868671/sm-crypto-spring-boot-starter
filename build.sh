#!/usr/bin/env bash
#
# 无 Maven 环境下的编译与自测脚本（用本地 ~/.m2 仓库里的 jar 拼 classpath）。
#
#   ./build.sh            # 编译 + 跑自测
#   ./build.sh compile    # 只编译
#   ./build.sh test       # 只跑自测（需已编译）
#   ./build.sh keys       # 生成前端对 + 后端对两套密钥对到 ./keys
#
# 生产项目请直接用 Maven：mvn clean package
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

R="${HOME}/.m2/repository"

# 与 pom.xml 中声明的版本保持一致（Spring Boot 3.5.16 → Spring Framework 6.2.x）
JARS=(
  "cn/hutool/hutool-all/5.8.33/hutool-all-5.8.33.jar"
  "org/bouncycastle/bcprov-jdk18on/1.80.2/bcprov-jdk18on-1.80.2.jar"
  "org/slf4j/slf4j-api/2.0.18/slf4j-api-2.0.18.jar"
  "com/fasterxml/jackson/core/jackson-databind/2.19.4/jackson-databind-2.19.4.jar"
  "com/fasterxml/jackson/core/jackson-core/2.19.4/jackson-core-2.19.4.jar"
  "com/fasterxml/jackson/core/jackson-annotations/2.19.4/jackson-annotations-2.19.4.jar"
  "com/fasterxml/jackson/datatype/jackson-datatype-jsr310/2.19.4/jackson-datatype-jsr310-2.19.4.jar"
  "org/springframework/boot/spring-boot/3.5.16/spring-boot-3.5.16.jar"
  "org/springframework/boot/spring-boot-autoconfigure/3.5.16/spring-boot-autoconfigure-3.5.16.jar"
  "org/springframework/spring-core/6.2.19/spring-core-6.2.19.jar"
  "org/springframework/spring-beans/6.2.19/spring-beans-6.2.19.jar"
  "org/springframework/spring-context/6.2.19/spring-context-6.2.19.jar"
  "org/springframework/spring-aop/6.2.19/spring-aop-6.2.19.jar"
  "org/springframework/spring-expression/6.2.19/spring-expression-6.2.19.jar"
  "org/springframework/spring-web/6.2.19/spring-web-6.2.19.jar"
  "org/springframework/spring-webmvc/6.2.19/spring-webmvc-6.2.19.jar"
  "jakarta/servlet/jakarta.servlet-api/6.0.0/jakarta.servlet-api-6.0.0.jar"
)

CP=""
MISSING=()
for j in "${JARS[@]}"; do
  if [ -f "$R/$j" ]; then
    CP="$CP$R/$j:"
  else
    MISSING+=("$j")
  fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "缺少依赖（请用 Maven 执行 mvn dependency:resolve 下载，或调整本脚本中的版本）："
  printf '  %s\n' "${MISSING[@]}"
  exit 1
fi

CLASSES="$HERE/build/classes"
PKG="com/github/william853868671/smcrypto"

compile() {
  rm -rf "$CLASSES"
  mkdir -p "$CLASSES"
  find src/main/java src/test/java -name '*.java' > build/sources.txt
  echo ">>> javac 编译 $(wc -l < build/sources.txt | tr -d ' ') 个源文件"
  javac -encoding UTF-8 -nowarn -cp "$CP" -d "$CLASSES" @"build/sources.txt"
  echo ">>> 编译通过"
}

run_self_test() {
  echo
  java -cp "$CLASSES:$CP" com.github.william853868671.smcrypto.SecurePayloadSelfTest build/selftest
}

gen_keys() {
  java -cp "$CLASSES:$CP" com.github.william853868671.smcrypto.tool.GenKeyPairTool --out ./keys
}

# 跨语言互通验证：Java(Hutool) 产物 → JS(sm-crypto) 解密，再反向。
# 需要 sm-crypto，若未安装：npm i sm-crypto，然后 export NODE_PATH=<node_modules 路径>
interop() {
  local node_bin="${NODE_BIN:-node}"
  echo ">>> [1/2] 小程序端 sm-crypto 解密后端返回体"
  if ! NODE_PATH="${NODE_PATH:-}" "$node_bin" tools/interop/verify-interop.js build/selftest; then
    echo "（若提示找不到 sm-crypto，请先 npm i sm-crypto 并设置 NODE_PATH）"
    return 1
  fi
  echo
  echo ">>> [2/2] 后端解密小程序产物"
  java -cp "$CLASSES:$CP" com.github.william853868671.smcrypto.InteropPeerCheck build/selftest
}

case "${1:-all}" in
  compile) compile ;;
  test)    run_self_test ;;
  keys)    gen_keys ;;
  interop) interop ;;
  all)     compile; run_self_test ;;
  *)       echo "用法: $0 [compile|test|keys|interop|all]"; exit 1 ;;
esac
