#!/usr/bin/env bash
#
# sm-crypto-spring-boot-starter-boot2 的本地辅助脚本（Spring Boot 2.7 / Java 8）。
#
#   ./build.sh            # mvn compile + 跑纯 Java 自测（SecurePayloadSelfTest）
#   ./build.sh compile    # 只编译（release 8）
#   ./build.sh test       # 只跑 Maven 测试（含 MockMvc 集成测试）
#   ./build.sh keys       # 生成前端对 + 后端对两套密钥对到 ./keys
#   ./build.sh self       # 只跑纯 Java 自测套件（不依赖 JUnit / Spring）
#
# 说明：本脚本依赖同仓库根目录下的 .tooling/apache-maven-3.9.9；使用 Maven 解析
# Spring Boot 2.7 的正确依赖（注意是 javax.servlet，不是 jakarta.servlet），
# 避免手写 jar 清单出错。生产发布请用 mvn clean deploy。
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# 优先使用仓库内自带的 Maven，否则回退到 PATH 上的 mvn
if [ -x "$HERE/../.tooling/apache-maven-3.9.9/bin/mvn" ]; then
  MVN="$HERE/../.tooling/apache-maven-3.9.9/bin/mvn"
else
  MVN="mvn"
fi

CLASSES="$HERE/target/classes"

# 用 Maven 解析编译期 classpath 到文件，避免手写 jar 清单（尤其 servlet API 的 javax/jakarta 差异）
build_classpath() {
  "$MVN" -o -q dependency:build-classpath -Dmdep.outputFile=build/cp.txt >/dev/null 2>&1 \
    || "$MVN" -q dependency:build-classpath -Dmdep.outputFile=build/cp.txt >/dev/null
}

ensure_compiled() {
  if [ ! -f "$CLASSES/com/github/william853868671/smcrypto/tool/GenKeyPairTool.class" ]; then
    echo ">>> 未检测到编译产物，先编译（release 8）"
    "$MVN" -o -q compile || "$MVN" -q compile
  fi
}

compile() {
  "$MVN" -o -q compile || "$MVN" -q compile
}

run_self_test() {
  ensure_compiled
  build_classpath
  echo ">>> 纯 Java 国密链路自测"
  java -cp "$CLASSES:$(cat build/cp.txt)" \
    com.github.william853868671.smcrypto.SecurePayloadSelfTest build/selftest
}

gen_keys() {
  ensure_compiled
  build_classpath
  java -cp "$CLASSES:$(cat build/cp.txt)" \
    com.github.william853868671.smcrypto.tool.GenKeyPairTool --out ./keys
}

case "${1:-all}" in
  compile) compile ;;
  test)    "$MVN" -o test || "$MVN" test ;;
  keys)    gen_keys ;;
  self)    run_self_test ;;
  all)     compile; run_self_test ;;
  *)       echo "用法: $0 [compile|test|keys|self|all]"; exit 1 ;;
esac
