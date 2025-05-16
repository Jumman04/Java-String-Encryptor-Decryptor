<?php
/**
 * Jummania.php
 *
 * Replicates the Java Jummania class in PHP:
 * 1. Generates an AES-128 key, encodes it without padding, shifts each char +1
 * 2. Reverses that to recover the raw key
 * 3. Encrypts a URL with AES/ECB/PKCS5Padding, Base64-encodes it, then shifts each char −1
 * 4. Shifts back +1, Base64-decodes, and decrypts to recover the original URL
 */


$string = $_GET['string'] ?? null;

if (!$string) {
    // Build current URL without query string
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https" : "http";
    $host = $_SERVER['HTTP_HOST'];
    $path = $_SERVER['PHP_SELF']; // script path

    $currentUrl = $scheme . "://" . $host . $path;

    $javaCode = <<<JAVA
Exception in thread "main" java.lang.IllegalStateException: string must not be null
	at com.jummania.link.Main.main(Main.java:10)

Usage: {$currentUrl}?string=your_encrypted_text_here
JAVA;

    showJavaCode($javaCode);
    exit();
}


// 1. Generate a lightweight AES-128 key (16 raw bytes)
$base64Key = rtrim(base64_encode(random_bytes(16)), '=');

// 2. Obfuscate the key: shift each character by +1
$encKeyChars = '';
for ($i = 0, $l = strlen($base64Key); $i < $l; $i++) {
    $encKeyChars .= chr(ord($base64Key[$i]) + 1);
}

// 3. Function to reverse key obfuscation
function getSecretKey(string $keyStr): string
{
    $decoded = '';
    for ($i = 0, $l = strlen($keyStr); $i < $l; $i++) {
        $decoded .= chr(ord($keyStr[$i]) - 1);
    }
    return base64_decode($decoded);
}

$secretKey = getSecretKey($encKeyChars);

// 4. Encrypt the text and shift each char by -1
function encryptShift(string $plainText, string $key): string
{
    $encrypted = openssl_encrypt($plainText, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
    $b64 = base64_encode($encrypted);

    $shifted = '';
    for ($i = 0, $l = strlen($b64); $i < $l; $i++) {
        $shifted .= chr(ord($b64[$i]) - 1);
    }
    return $shifted;
}

$shiftedEnc = encryptShift($string, $secretKey);


$javaCode = <<<JAVA
public class Jummania {
    public static String getString() {
        javax.crypto.SecretKey secretKey = getSecretKey("$encKeyChars");
        return getString(secretKey, "$shiftedEnc");
    }

    public static javax.crypto.SecretKey getSecretKey(String key) {
        String string = shiftChars(key, -1);
        byte[] decodedKey = java.util.Base64.getDecoder().decode(string);
        return new javax.crypto.spec.SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static String getString(javax.crypto.SecretKey secretKey, String encryptedText) {
        try {
            String string = shiftChars(encryptedText, 1);
            java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
            byte[] encryptedTextByte = decoder.decode(string);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(encryptedTextByte));
        } catch (Exception e) {
            return null;
        }

    }

    public static String shiftChars(String input, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            result.append((char) (c + shift));
        }
        return result.toString();
    }
}
JAVA;

showJavaCode($javaCode);

function showJavaCode(string $javaCode)
{
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Java Code</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/default.min.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/java.min.js"></script>
        <script>hljs.highlightAll();</script>
    </head>
    <body>
    <pre><code class="language-java"><?php echo htmlspecialchars($javaCode); ?></code></pre>
    </body>
    </html>
    <?php
    exit();
}