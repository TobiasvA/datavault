package de.vanark.datavault;

import de.cimt.talendcomp.checksum.HashCalculation;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionTest {
    private final String secretKey = Encryption.generateSecretKey();
    @Test
    public void encrypt() throws InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, DecoderException {
        System.out.println(secretKey);
        String encryptedValues;
        encryptedValues = Encryption.encrypt(secretKey, 1);
        System.out.println(encryptedValues);
        encryptedValues = Encryption.encrypt(secretKey, 4711);
        System.out.println(encryptedValues);
        encryptedValues = Encryption.encrypt(secretKey, 125698456223L);
        System.out.println(encryptedValues);
        encryptedValues = Encryption.encrypt(secretKey, new Date());
        System.out.println(encryptedValues);
        encryptedValues = Encryption.encrypt(secretKey, "Hallo!", 12);
        System.out.println(encryptedValues);
        String decrypted = Encryption.decrypt(encryptedValues, secretKey);
        System.out.println(decrypted);
    }

    @Test
    public void hash() {
        GlobalHashNormalization.DEFAULT_NORMALIZATION.reset();
        GlobalHashNormalization.DEFAULT_NORMALIZATION.add("some boring text!", GlobalHashNormalization.DEFAULT_OBJECT_CONFIG);
        GlobalHashNormalization.DEFAULT_NORMALIZATION.calculateHash("SHA1", HashCalculation.HASH_OUTPUT_ENCODINGS.HEX);
        String hash = HashCalculation.getSHA1Hash("some boring text!", HashCalculation.HASH_OUTPUT_ENCODINGS.HEX);
        System.out.println(hash);
        assertEquals(hash, "4b9269065cbc2dd5041e349cb54102354751925a");
    }
}