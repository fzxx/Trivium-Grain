# Trivium-Grain 算法库

由**风之暇想**编写的 JavaScript 实现的 Trivium、Grain v1 算法库。

## 在线预览

[https://trivium-grain.js.org/](https://trivium-grain.js.org/)

## 使用示例

```javascript
// Trivium 加密/解密
const ciphertext1 = TriviumGrain.encrypt('trivium', key80bits, iv80bits, plaintext);
const plaintext1 = TriviumGrain.decrypt('trivium', key80bits, iv80bits, ciphertext1);

// Grain v1 加密/解密  
const ciphertext2 = TriviumGrain.encrypt('grain', key80bits, iv64bits, plaintext);
const plaintext2 = TriviumGrain.decrypt('grain', key80bits, iv64bits, ciphertext2);
```

### 算法规格
| 算法 | 密钥长度 | IV长度 | 认证 |
|------|---------|--------|------|
| Trivium | 10字节 | 10字节 | ❌ |
| Grain v1 | 10字节 | 8字节 | ❌ |

### 密钥流生成
```javascript
// Trivium 密钥流
const triviumGen = TriviumGrain.triviumKeystreamGen(key80bits, iv80bits);
const keystreamByte = triviumGen.next().value;

// Grain v1 密钥流
const grainGen = TriviumGrain.grainKeystreamGen(key80bits, iv64bits);
const keystreamByte = grainGen.next().value;
```

## 注意事项

- 密钥和IV必须使用密码学安全随机数生成器
- **相同密钥**下，IV绝对不能重复（会导致安全漏洞）

## 开源协议
[GNU Affero General Public License v3.0](https://github.com/fzxx/Trivium-Grain/blob/main/LICENSE)