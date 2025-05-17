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
     * Retrieves the decrypted original string using hardcoded obfuscated input and a predefined secret key.
     * <p>
     * This method uses a hardcoded string as the AES key (in obfuscated form) and another hardcoded
     * string as the encrypted input. It reconstructs the AES {@link javax.crypto.SecretKey} from the key,
     * then decrypts the encrypted input (which has been character-shifted and Base64-encoded) to return
     * the original plain text.
     *
     * @return the decrypted original plain text
     * @throws Exception if any error occurs during secret key reconstruction or decryption
     */
    public String getString() throws Exception {
        return getString("$encKeyChars", "$shiftedEnc");
    }
    
    
     /**
     * Decrypts an obfuscated and Base64-encoded string using AES with the provided secret key.
     * <p>
     * The decryption process involves three steps:
     * <ol>
     *   <li>Reverse the character shift applied during encryption (each character is decremented by 1).</li>
     *   <li>Decode the result from Base64 to obtain the original encrypted bytes.</li>
     *   <li>Decrypt the bytes using the AES algorithm and the given secret key.</li>
     * </ol>
     *
     * @param secretKey     the string used to derive the AES {@link javax.crypto.SecretKey} for decryption
     * @param encryptedText the input string that was obfuscated, Base64-encoded, and AES-encrypted
     * @return the original plaintext string after successful decryption
     * @throws Exception if any step of the decryption process fails (e.g., Base64 decoding, cipher setup, or AES decryption)
     */
    private String getString(String secretKey, String encryptedText) throws Exception {
        String string = shiftChars(encryptedText, 1);
        java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
        byte[] encryptedTextByte = decoder.decode(string);
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, getSecretKey(secretKey));
        return new String(cipher.doFinal(encryptedTextByte));
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