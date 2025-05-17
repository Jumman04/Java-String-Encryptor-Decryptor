<?php
/**
 * Jummania.php
 *
 * A PHP implementation that mirrors the functionality of the Java `Jummania` class.
 *
 * Features:
 * 1. Generates a 128-bit AES key, Base64-encodes it (without padding), and shifts each character by +1.
 * 2. Reverses the obfuscation to recover the raw key by shifting characters by -1 and Base64-decoding.
 * 3. Encrypts a URL using AES/ECB/PKCS5Padding, Base64-encodes the result, and shifts each character by -1.
 * 4. To decrypt, shifts characters back by +1, Base64-decodes, and decrypts to retrieve the original URL.
 *
 * Author: Jummania
 * Date: 2024-05-14
 * Email: sharifuddinjumman@gmail.com
 * Location: Dhaka, Bangladesh
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

// 2. Reusable function to shift characters
function shiftChars(string $input, int $shift): string
{
    $output = '';
    for ($i = 0, $l = strlen($input); $i < $l; $i++) {
        $output .= chr(ord($input[$i]) + $shift);
    }
    return $output;
}

// 2. Obfuscate the key: shift each character by +1
$encKeyChars = shiftChars($base64Key, +1);
$secretKey = base64_decode(shiftChars($encKeyChars, -1));

// 4. Encrypt the text and shift each char by -1
function encryptShift(string $plainText, string $key): string
{
    $encrypted = openssl_encrypt($plainText, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
    $b64 = rtrim(base64_encode($encrypted), '=');

    $shifted = '';
    for ($i = 0, $l = strlen($b64); $i < $l; $i++) {
        $shifted .= chr(ord($b64[$i]) - 1);
    }
    return $shifted;
}

$shiftedEnc = encryptShift($string, $secretKey);

$created = date("d/n/y");
$javaCode = <<<JAVA
/**
 * The {@code Jummania} class demonstrates AES encryption key reconstruction and
 * decryption of a string that was obfuscated using character shifting and Base64 encoding.
 * <p>
 * This is an example of lightweight obfuscation layered on top of symmetric encryption,
 * suitable for scenarios where additional obscurity is desired beyond encryption.
 * 
 * <p><b>Note:</b> This code is for educational or internal use only and not recommended for
 * production-grade cryptographic implementations.
 * 
 * <p><b>Created by:</b> Jummania  
 * <br><b>Date:</b> $created
 * <br><b>Email:</b> sharifuddinjumman@gmail.com  
 * <br><b>Location:</b> Dhaka, Bangladesh
 */
public class Jummania {


    /**
     * Retrieves the decrypted original string using a hardcoded encrypted text and secret key.
     * <p>
     * This method internally constructs a {@link javax.crypto.SecretKey} from a predefined obfuscated Base64 key string,
     * and then decrypts a predefined obfuscated and Base64-encoded string using that key.
     *
     * @return the decrypted original string
     * @throws Exception if any error occurs during key reconstruction or decryption
     */
    public String getString() throws Exception {
        javax.crypto.SecretKey secretKey = getSecretKey("$encKeyChars");
        return getString(secretKey, "$shiftedEnc");
    }


    /**
     * Converts an obfuscated Base64-encoded AES key string into a SecretKey object.
     * The input string is shifted by -1 on each character before Base64 decoding.
     * 
     * @param key The obfuscated Base64-encoded AES key string
     * @return SecretKey instance for AES algorithm
     */
    private javax.crypto.SecretKey getSecretKey(String key) {
        String string = shiftChars(key, -1);
        byte[] decodedKey = java.util.Base64.getDecoder().decode(string);
        return new javax.crypto.spec.SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }


    /**
     * Decrypts an encrypted Base64-encoded string using the provided AES secret key.
     * <p>
     * The input string is first character-shifted (each character increased by 1),
     * then decoded from Base64, and finally decrypted using AES.
     *
     * @param secretKey     the AES {@link javax.crypto.SecretKey} used for decryption
     * @param encryptedText the obfuscated and Base64-encoded string to decrypt
     * @return the original plain text after decryption
     * @throws Exception if any decryption step fails (e.g., decoding, cipher initialization, or decryption)
     */
    private String getString(javax.crypto.SecretKey secretKey, String encryptedText) throws Exception {
        String string = shiftChars(encryptedText, 1);
        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(string);
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(encryptedTextByte));
    }


    /**
     * Applies a character-wise shift to each character in the input string.
     * For each character c, returns (char)(c + shift).
     * 
     * @param input The input string to be shifted
     * @param shift The integer shift to apply (positive or negative)
     * @return The shifted string after applying the character shift
     */
    private String shiftChars(String input, int shift) {
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