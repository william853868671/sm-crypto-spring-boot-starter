#!/usr/bin/env node
/**
 * 解密一条真实 HTTP 响应 —— 完全按小程序端流程走，验证线上联通性。
 *
 * 用法：
 *   NODE_PATH=<node_modules> node decrypt-http-response.js <响应文件> <私钥文件>
 *
 * 例：
 *   curl -s http://127.0.0.1:18080/api/order/5 > response.json
 *   NODE_PATH=... node decrypt-http-response.js response.json keys/sm2-private-key.txt
 */
const fs = require('fs');

const sm2 = require('sm-crypto/src/sm2');
const sm4 = require('sm-crypto/src/sm4');

const responseFile = process.argv[2];
const privateKeyFile = process.argv[3];

if (!responseFile || !privateKeyFile) {
  console.error('用法: node decrypt-http-response.js <响应文件> <私钥文件>');
  process.exit(1);
}

const payload = JSON.parse(fs.readFileSync(responseFile, 'utf8'));
const privateKey = fs.readFileSync(privateKeyFile, 'utf8').trim();

console.log('--- 收到的响应（密文态） ---');
console.log('code =', payload.code);
console.log('data =', payload.data.slice(0, 60) + '... (' + payload.data.length + ' 字符)');
console.log('key  =', payload.key.slice(0, 60) + '... (' + payload.key.length + ' 字符)');
console.log();

console.log('--- 第 1 步：SM2 私钥解出 SM4 密钥 ---');
const sm4Key = sm2.doDecrypt(payload.key, privateKey, 1);
console.log('SM4 key =', sm4Key);

console.log('\n--- 第 2 步：拆分 IV 与密文 ---');
const raw = Buffer.from(payload.data, 'base64');
const iv = raw.subarray(0, 16);
const cipher = raw.subarray(16);
console.log(`总 ${raw.length} 字节 = IV ${iv.length} + 密文 ${cipher.length}`);
console.log('IV =', iv.toString('hex'));

console.log('\n--- 第 3 步：SM4-CBC 解密 ---');
const plain = sm4.decrypt(cipher.toString('hex'), sm4Key, {
  mode: 'cbc',
  iv: iv.toString('hex'),
  output: 'string',
});

console.log('明文 =', plain);
try {
  console.log('\n--- 业务数据（已解析） ---');
  console.log(JSON.stringify(JSON.parse(plain), null, 2));
} catch (e) {
  console.log('（明文不是 JSON：' + e.message + '）');
}
