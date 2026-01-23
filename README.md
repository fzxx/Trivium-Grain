# Trivium-Grain 算法库

由**风之暇想**编写的 JavaScript 实现的 Trivium、Grain v1 和 Grain128-AEAD 算法库。

## 在线预览

[https://trivium-grain.js.org/](https://trivium-grain.js.org/)

## 使用示例

### CDN引用

```html
<script src="https://cdn.jsdelivr.net/gh/fzxx/Trivium-Grain/TriviumGrain.js"></script>
```

```html
<script src="https://cdn.statically.io/gh/fzxx/Trivium-Grain@main/TriviumGrain.js"></script>
```

### 调用代码

```javascript
// Trivium 加密/解密
const ciphertext1 = TriviumGrain.encrypt('trivium', key80bits, iv80bits, plaintext);
const plaintext1 = TriviumGrain.decrypt('trivium', key80bits, iv80bits, ciphertext1);

// Grain v1 加密/解密  
const ciphertext2 = TriviumGrain.encrypt('grain', key80bits, iv64bits, plaintext);
const plaintext2 = TriviumGrain.decrypt('grain', key80bits, iv64bits, ciphertext2);

// Grain128-AEAD 加密/解密（带认证）
const ciphertext3 = TriviumGrain.encrypt('grain128aead', key16bytes, iv12bytes, plaintext, associatedData);
const plaintext3 = TriviumGrain.decrypt('grain128aead', key16bytes, iv12bytes, ciphertext3, associatedData);
```

### 算法规格
| 算法 | 密钥长度 | IV长度 | 认证 |
|------|---------|--------|------|
| Trivium | 10字节 | 10字节 | ❌ |
| Grain v1 | 10字节 | 8字节 | ❌ |
| Grain128-AEAD | 16字节 | 12字节 | ✅ |

### 密钥流生成
```javascript
// Trivium 密钥流
const triviumGen = TriviumGrain.triviumKeystreamGen(key80bits, iv80bits);
const keystreamByte = triviumGen.next().value;

// Grain v1 密钥流
const grainGen = TriviumGrain.grainKeystreamGen(key80bits, iv64bits);
const keystreamByte = grainGen.next().value;
```

## 级联建议

- 虽然可以自由组合，但建议使用同为128位安全的算法，并且**最后一层加密使用带验证的算法**
  - 明文 → Trivium → **Grain128-AEAD** → 密文
  - 明文 → Trivium → **Ascon-AEAD128** → 密文
  - 明文 → Aes-128 → **Grain128-AEAD** → 密文
  - 明文 → Aes-128 → ChaCha12 → **Ascon-AEAD128** → 密文

## 注意事项

- 密钥和IV必须使用密码学安全随机数生成器
- **相同密钥**下，IV绝对不能重复（会导致安全漏洞）

## 开源协议
[GNU Affero General Public License v3.0](https://github.com/fzxx/Trivium-Grain/blob/main/LICENSE)