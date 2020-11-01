package de.vanark.datavault;

import de.cimt.encryption.Encryption;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class AesEncryption {
    public static final String encryptionKeyForNull = "!#!null!#!";
    public static final String encryptionKeyForMissing = "!#!missing!#!";
    public static String generateBase64Key() throws NoSuchAlgorithmException {
        SecretKey key = Encryption.getSecretKey();
        return Encryption.secretKeyToBase64(key);
    }

    public static String encrypt(Object input, String base64Key) throws Exception {
        if(encryptionKeyForNull.equalsIgnoreCase(base64Key.trim())) return null;
        if(encryptionKeyForMissing.equalsIgnoreCase(base64Key.trim())) return null;
        String normalizedInput = Encryption.normalizeEncryptionInput(input);
        return Encryption.encryptToBase64(normalizedInput, Encryption.base64StringToSecretKey(base64Key));
    }
}
