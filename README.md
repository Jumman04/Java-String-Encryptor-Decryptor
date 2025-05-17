# 🔐 Java String Encryptor Code Generator (PHP Tool)

A lightweight PHP tool that generates Java code to **securely decrypt encrypted strings at runtime** — designed to keep
sensitive data hidden from Java decompilers.

---

## 🧠 How It Works

Instead of embedding your **original string** directly in Java code (which can be exposed by decompilers), this tool:

1. **Encrypts and obfuscates** the input string using AES-128 + character shifting.
2. **Generates Java code** that includes only the encrypted version.
3. In Java, when the generated function is called, the string is decrypted **at runtime** — not hardcoded.

This keeps your original string hidden and safe.

---

## ✅ Features

- AES-128 encryption in ECB mode with PKCS5Padding
- Character shifting for added obfuscation
- Java-compatible output
- Clean, readable Java code output
- No original string exposed in code — only decrypted at runtime

---

## 🌐 Usage

Visit:

[https://jummania.com/App/java-string-encryptor/](https://jummania.com/App/java-string-encryptor/)

The tool will return valid Java code with your encrypted string and auto-decryption logic.

---

## 🧪 Example

### Input:

https://jummania.com/App/java-string-encryptor/?string=YourSecretText

### Output Java Code:

```java
public class Jummania {

    public String getString() {
        return getString("8NkWOL8SbIqWyz0nlPzsCR...", "AnvNJBmt6d2Fjc66U1KCnP...");
    }

}
```
