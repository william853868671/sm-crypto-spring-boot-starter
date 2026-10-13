#!/usr/bin/env node
/**
 * 跨语言互通验证 —— 模拟微信小程序端用 sm-crypto 解密后端（Hutool）返回的数据。
 *
 * 用法：
 *   NODE_PATH=<node_modules> node verify-interop.js <selftest 目录>
 *
 * 流程与小程序端完全一致：
 *   1. 用本地保存的 SM2 私钥解出 SM2 密文里的 SM4 密钥
 *   2. 把 Base64 密文拆成 IV(前16字节) + SM4 密文
 *   3. SM4-CBC 解密，得到业务 JSON
 *   4. 反向：用前端公钥加密一段文本，写出产物交给 Java 端解密
 */
const fs = require('fs');
const path = require('path');

const sm2 = require('sm-crypto/src/sm2');
const sm4 = require('sm-crypto/src/sm4');

const dir = process.argv[2] || 'build/selftest';
let pass = 0;
const failures = [];

function check(name, expected, actual) {
  const ok = expected === actual;
  if (ok) pass++;
  else failures.push(`${name}：期望=${expected} 实际=${actual}`);
  console.log(`${ok ? '  [OK]   ' : '  [FAIL] '}${name}${ok ? '' : `  期望=${expected} 实际=${actual}`}`);
}

function readKV(file) {
  const map = {};
  fs.readFileSync(file, 'utf8').split('\n').forEach((line) => {
    const i = line.indexOf('=');
    if (i > 0) map[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return map;
}

console.log('=========== 小程序端（sm-crypto）解密后端返回体 ===========\n');

const keys = readKV(path.join(dir, 'client-keys.properties'));
const payload = JSON.parse(fs.readFileSync(path.join(dir, 'payload.json'), 'utf8'));

console.log('[1] 后端返回体结构');
check('包含 code 字段', true, Object.prototype.hasOwnProperty.call(payload, 'code'));
check('包含 data 字段', true, Object.prototype.hasOwnProperty.call(payload, 'data'));
check('包含 key 字段', true, Object.prototype.hasOwnProperty.call(payload, 'key'));
check('code = 200', 200, payload.code);
check('data 长度为偶数（Base64）', 0, payload.data.length % 4);
check('key 不含 04 前缀（sm-crypto 期望格式）', false, payload.key.startsWith('04'));
console.log(`      data 共 ${payload.data.length} 字符 Base64，key 共 ${payload.key.length} 字符 hex`);

console.log('\n[2] 第一步：用前端私钥解出 SM4 密钥');
const sm4Key = sm2.doDecrypt(payload.key, keys.privateKey, 1);
check('SM4 密钥为 32 位 hex', 32, sm4Key.length);
console.log(`      解出 SM4 key = ${sm4Key}`);

console.log('\n[3] 第二步：拆分 IV 与密文');
const raw = Buffer.from(payload.data, 'base64');
const ivBuf = raw.slice(0, 16);
const cipherBuf = raw.slice(16);
check('IV 长度 = 16 字节', 16, ivBuf.length);
check('密文长度为 16 的整数倍', 0, cipherBuf.length % 16);
console.log(`      总长 ${raw.length} 字节 = IV ${ivBuf.length} + 密文 ${cipherBuf.length}`);

console.log('\n[4] 第三步：SM4-CBC 解密业务数据');
const plainJson = sm4.decrypt(cipherBuf.toString('hex'), sm4Key, {
  mode: 'cbc',
  iv: ivBuf.toString('hex'),
  output: 'string',
});
check('解密结果与后端预期一致', keys.expectedJson, plainJson);

let obj = null;
try {
  obj = JSON.parse(plainJson);
  check('密文是合法 JSON', true, true);
  check('orderNo 正确', 'SO2026101200010086', obj.orderNo);
  check('mobile 正确', '13800001234', obj.mobile);
  check('customerName（中文）正确', '东', obj.customerName);
  // 注意用原始字符串断言：JS 的 Number 没有尾零概念，JSON.parse 后 1999.00 会变成 1999
  check('金额精度保留（1999.00 而非 1999）', true, plainJson.includes('"amount":1999.00'));
  check('时间序列化为 ISO 字符串而非时间戳', true, plainJson.includes('"createdAt":"2026-10-12T14:30:00"'));
} catch (e) {
  check('密文是合法 JSON', '可解析', '解析失败: ' + e.message);
}
console.log(`      明文：${plainJson}`);

console.log('\n[5] 反向验证：小程序端加密，交给 Java 解密');
const peerPlain = '小程序上行数据-中文ABC-2026';
const peerCipher = sm2.doEncrypt(peerPlain, keys.publicKey, 1);
const peerSm4Key = sm4.generateKey ? sm4.generateKey() : require('crypto').randomBytes(16).toString('hex');
const peerSm4Iv = require('crypto').randomBytes(16).toString('hex');
const peerSm4Cipher = sm4.encrypt(peerPlain, peerSm4Key, { mode: 'cbc', iv: peerSm4Iv });
check('sm-crypto 能产出 SM2 密文', true, typeof peerCipher === 'string' && peerCipher.length > 0);
check('sm-crypto 能产出 SM4 密文', true, typeof peerSm4Cipher === 'string' && peerSm4Cipher.length > 0);

console.log('\n[6] 自解自验（确认测试脚本本身没写错）');
check('sm2 自解', peerPlain, sm2.doDecrypt(peerCipher, keys.privateKey, 1));
check('sm4 自解', peerPlain, sm4.decrypt(peerSm4Cipher, peerSm4Key, { mode: 'cbc', iv: peerSm4Iv }));

const peerFile = path.join(dir, 'peer-from-js.json');
fs.writeFileSync(peerFile, JSON.stringify({
  plain: peerPlain,
  sm2Cipher: peerCipher,
  sm4Key: peerSm4Key,
  sm4Iv: peerSm4Iv,
  sm4Cipher: peerSm4Cipher,
}, null, 2));
console.log(`      已写出 ${peerFile}（交给 Java 端解密）`);

console.log('\n=========== 结果 ===========');
console.log(`通过 ${pass} / ${pass + failures.length}`);
if (failures.length === 0) {
  console.log('>>> 全部通过：Hutool(Java) 密文可被 sm-crypto(小程序) 正确解密');
} else {
  console.log('>>> 失败项：');
  failures.forEach((f) => console.log('    - ' + f));
  process.exit(1);
}
