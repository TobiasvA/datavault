package de.vanark.datavault;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Encryption {
    private final static int KEY_SIZE = 16;

    public static String decrypt(String value, char[] key) throws DecoderException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        //byte[] keyBytes = Arrays.copyOf(strKey.getBytes("ASCII"), 16);
        byte[] keyBytes = Hex.decodeHex(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher decipher = Cipher.getInstance("AES");
        decipher.init(Cipher.DECRYPT_MODE, secretKey);
        char[] clearText = value.toCharArray();
        byte[] decodeHex = Hex.decodeHex(clearText);
        byte[] ciphertextBytes = decipher.doFinal(decodeHex);
        return new String(ciphertextBytes);
    }

    public static String encrypt(String key, Object... values) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, DecoderException {
        GlobalHashNormalization.DEFAULT_NORMALIZATION.reset();
        Arrays.stream(values)
                .forEach(v -> GlobalHashNormalization.DEFAULT_NORMALIZATION.add(
                        v,
                        GlobalHashNormalization.DEFAULT_OBJECT_CONFIG));
        String normalizedInput = GlobalHashNormalization.DEFAULT_NORMALIZATION.getNormalizedString();
        return encrypt(normalizedInput, key);
    }

    private static String encrypt(String normalizedInput, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, DecoderException {
            //byte[] keyBytes = Arrays.copyOf(key.getBytes(StandardCharsets.US_ASCII), KEY_SIZE);
            byte[] keyBytes = Hex.decodeHex(key);
            SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] clearText = normalizedInput.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextBytes = cipher.doFinal(clearText);

            return new String(Hex.encodeHex(ciphertextBytes));
    }

    public static String generateSecretKey() {
        byte[] array = new byte[KEY_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(array);
        //return Hex.encodeHex(array);
        return new String(array, StandardCharsets.US_ASCII);
    }
}
