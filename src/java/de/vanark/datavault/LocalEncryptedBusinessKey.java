package de.vanark.datavault;

import de.cimt.encryption.Encryption;
import de.cimt.talendcomp.checksum.NormalizeObjectConfig;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class LocalEncryptedBusinessKey extends EncryptedBusinessKey {
    private String[] encryptedValues;
    private String[] normalizedValues;
    private SecretKey secretKey;
    public LocalEncryptedBusinessKey(EncryptedHub<? extends EncryptedBusinessKey> hub, Object... values) throws Exception {
        super(hub, values);
    }

    public LocalEncryptedBusinessKey(EncryptedHub<? extends EncryptedBusinessKey> hub, String hashedEncryption, String hash, Object... values) {
        super(hub, hashedEncryption, hash, values);
    }

    private void encrypt() throws EncryptBusinessKeyException {
        final SecretKey secretKey = getSecretKey();
        encryptedValues = new String[getHub().getSize()];
        final Object[] encryptedKeyValues = new Object[getHub().getSize()];
        final NormalizeObjectConfig[] configs = new NormalizeObjectConfig[getHub().getSize()];
        for (short i = 0; i < getHub().getSize(); i++)
            if (getHub().getKeyConfig(i).isEncrypted()) {
                final String normalizedValue = getNormalizedValue(i);
                final byte[] encryptedBytes;
                try {
                    encryptedBytes = Encryption.encryptToBytes(normalizedValue, secretKey);
                } catch (Exception exception) {
                    throw new EncryptBusinessKeyException(
                            "Unable to encrypt value \"" + normalizedValue + "\"!",
                            exception);
                }
                encryptedValues[i] = Hex.encodeHexString(encryptedBytes);
                encryptedKeyValues[i] = encryptedValues[i];
                configs[i] = getHub().getKeyConfig(i);
            } else {
                encryptedKeyValues[i] = getValue(i);
                configs[i] = GlobalHashNormalization.DEFAULT_OBJECT_CONFIG;
            }
        final String hashedEncryption = EncryptedHub.hash(encryptedKeyValues, configs);
        setHashedEncryption(hashedEncryption);
    }

    private SecretKey getSecretKey() throws EncryptBusinessKeyException {
        if (secretKey == null) {
            String hexKey = getEncryptionKey();
            byte[] decoded;
            try {
                decoded = Hex.decodeHex(hexKey);
            } catch (DecoderException exception) {
                throw new EncryptBusinessKeyException("Can't decode encryptionKey!", exception);
            }
            secretKey = new SecretKeySpec(decoded, 0, decoded.length, "AES");
        }
        return secretKey;

    }

    @Override
    String getEncryptedValue(short index) throws EncryptBusinessKeyException {
        if (encryptedValues == null) encrypt();
        return encryptedValues[index];
    }

    @Override
    String getHashedEncryption() throws EncryptBusinessKeyException {
        if (super.getHashedEncryption() == null) encrypt();
        return super.getHashedEncryption();
    }

    private String getNormalizedValue(short index) {
        if (normalizedValues == null)
            normalizedValues = new String[getHub().getSize()];
        if (normalizedValues[index] == null) {
            GlobalHashNormalization.DEFAULT_NORMALIZATION.reset();
            GlobalHashNormalization.DEFAULT_NORMALIZATION.add(getValue(index), getHub().getKeyConfig(index));
            normalizedValues[index] = GlobalHashNormalization.DEFAULT_NORMALIZATION.getNormalizedString();
        }
        return normalizedValues[index];
    }
}
