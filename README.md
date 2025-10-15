## 📦 `@notifycode/hash-it`

> Lightweight, secure, and flexible token encryption/decryption using AES-256-CBC — built with Bun + TypeScript.

---

### 🔐 Features

* 🔒 AES-256-CBC encryption
* 🔑 Flexible key length (min 6 characters)
* 🧠 Secure PBKDF2 key derivation
* ⚡ Fully typed with TypeScript
* 🐰 Built for **Bun** (also works in **Node.js**)
* 📦 Zero external dependencies

---

### 🚀 Installation

Using **Bun**:

```bash
bun add @notifycode/hash-it
```

Using **npm**:

```bash
npm install @notifycode/hash-it
```

---

### 📚 Usage

```ts
import { hashToken, decodeHashedToken } from '@notifycode/hash-it';

const key = 'supersecret123';           // Must be at least 6 characters
const token = 'this-is-a-token';        // Your original token

// Encrypt (hash) the token
const encrypted = hashToken({ token, key });
console.log('Encrypted:', encrypted);

// Decrypt the token back
const decrypted = decodeHashedToken({ token: encrypted, key });
console.log('Decrypted:', decrypted); // ➜ "this-is-a-token"
```

---

### 📘 API

#### `hashToken({ token, key })`

Encrypts the provided `token` using a derived AES-256 key.

* `token` *(string)* – The original string to encrypt
* `key` *(string)* – Your secret key (min 6 characters)

Returns: A base64-encoded string in the format `IV:EncryptedToken`.

---

#### `decodeHashedToken({ token, key })`

Decrypts the token previously encrypted with `hashToken`.

* `token` *(string)* – The encrypted string returned by `hashToken`
* `key` *(string)* – The same key used to encrypt

Returns: The original plain text token.

---

### 📦 How It Works

1. Key is derived using `PBKDF2` from your input key.
2. AES-256-CBC is used for encryption with a random IV.
3. IV and encrypted data are combined and base64-encoded.
4. To decrypt, the IV is extracted and used to reconstruct the cipher.

---