#!/usr/bin/env node
/**
 * 加密一个请求体并演示如何发出 —— 与 decrypt-http-response.js 完全对称。
 * 前端（小程序）发送加密请求时用此流程：用【后端公钥】加密、带 X-SmCFBEncrypt: true。
 *
 * 用法：
 *   NODE_PATH=<node_modules> node encrypt-http-request.js <明文json文件> <后端公钥文件>
 *
 * 例：
 *   echo '{"orderId":5,"amount":1999.00}' > plain.json
 *   NODE_PATH=... node encrypt-http-request.js plain.json keys/smcfb-frontend.txt
 *   # server-public-key 在 smcfb-frontend.txt 里；也可单独存一个文件只放后端公钥
 */
const fs = require('fs');
const crypto = require('crypto');

const sm2 = require('sm-crypto/src/sm2');
const sm4 = require('sm-crypto/src/sm4');

const plainFile = process.argv[2];
const serverPublicKeyFile = process.argv[3];

if (!plainFile || !serverPublicKeyFile) {
  console.error('用法: node encrypt-http-request.js <明文json文件> <后端公钥文件>');
  process.exit(1);
}

const plain = fs.readFileSync(plainFile, 'utf8').trim();
// 兼容传入 smcfb-frontend.txt（含 client-private-key / server-public-key 两行）
const raw = fs.readFileSync(serverPublicKeyFile, 'utf8');
const m = raw.match(/server-public-key:\s*(\S+)/);
const serverPublicKey = (m ? m[1] : raw).trim();

console.log('--- 原始明文 ---');
console.log(plain);
console.log();

console.log('--- 第 1 步：生成随机 SM4 密钥 + IV ---');
const sm4Key = crypto.randomBytes(16).toString('hex'); // 32 hex（16 字节）
const iv = crypto.randomBytes(16);                     // 16 字节 IV
const ivHex = iv.toString('hex');
console.log('SM4 key =', sm4Key);
console.log('IV      =', ivHex);

console.log('\n--- 第 2 步：SM4-CBC 加密业务数据 ---');
// sm-crypto 的 sm4.encrypt 接受字符串 key；output:'hex' 返回 hex 密文
const cipherHex = sm4.encrypt(plain, sm4Key, { mode: 'cbc', iv: ivHex, output: 'hex' });
const payload = Buffer.concat([iv, Buffer.from(cipherHex, 'hex')]);
const data = payload.toString('base64');
console.log('data    =', data.slice(0, 60) + '... (' + data.length + ' 字符)');

console.log('\n--- 第 3 步：用后端公钥 SM2 加密 SM4 密钥 ---');
// cipherMode = 1 → 无 04 前缀的 C1C3C2，与 Java 端 sm2Encrypt 对齐
const key = sm2.doEncrypt(sm4Key, serverPublicKey, 1);
console.log('key     =', key.slice(0, 60) + '... (' + key.length + ' 字符)');

const body = JSON.stringify({ data, key });
console.log('\n--- 请求体（密文态） ---');
console.log(body);
console.log('\n--- 发送时务必带上请求头 ---');
console.log('X-SmCFBEncrypt: true');
