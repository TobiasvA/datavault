package de.vanark.datavault;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.StringJoiner;

public class DBEncryptedBusinessKey extends EncryptedBusinessKey {
    private final static String encryptionFunction = "hex(aes_encrypt({value}, {key}))";
    private final static String hashFunction = "sha2({value}, 256)";

    private String[] encryptedValues;
    private String[] normalizedValues;

    public DBEncryptedBusinessKey(EncryptedHub<DBEncryptedBusinessKey> hub, Object... values) throws Exception {
        super(hub, values);
    }

    public DBEncryptedBusinessKey(EncryptedHub<DBEncryptedBusinessKey> hub, String hashedEncryption, String hash, Object... values) {
        super(hub, hashedEncryption, hash, values);
    }

    private String buildEncryptionCall(short index) {
        return encryptionFunction
                .replace("{key}", "'" + getEncryptionKey() + "'")
                .replace("{value}", "'" + getNormalizedValue(index) + "'");
    }

    private String buildHashEncryptionCall() {
        final StringJoiner value;
        value = new StringJoiner("||'"+ GlobalHashNormalization.DEFAULT_CONFIG.getDelimter() + "'||");
        for (short i = 0; i < getHub().getSize(); i++) {
            value.add((getHub().getKeyConfig(i).isEncrypted()) ? buildEncryptionCall(i) : getNormalizedValue(i));
        }
        return hashFunction
                .replace("{value}", value.toString());
    }

    private void encrypt() throws EncryptBusinessKeyException {
        try {
            setSQLMode();
        } catch (SQLException exception) {
            throw new EncryptBusinessKeyException("Can't set sqlMode 'PIPES_AS_CONCAT'!", exception);
        }
        encryptedValues = new String[getHub().getSize()];
        final StringJoiner selections = new StringJoiner(", ")
                .add(buildHashEncryptionCall());
        for (short index = 0; index < getHub().getSize(); index++)
            if (getHub().getKeyConfig(index).isEncrypted())
                selections.add(buildEncryptionCall(index));
            else
                selections.add("null");
        String query = "select " + selections.toString();
        try {
            Statement statement = getHub().getConnection().createStatement();
            ResultSet result = statement.executeQuery(query);
            result.next();
            setHashedEncryption(result.getString(1));
            for (short index = 0; index < getHub().getSize(); index++)
                if (getHub().getKeyConfig(index).isEncrypted()) {
                    encryptedValues[index] = result.getString(index + 2);
                }
            result.close();
            statement.close();
        } catch (SQLException exception) {
            System.err.println(query);
            throw new EncryptBusinessKeyException("Can't query encrypted values!", exception);
        }
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

    private void setSQLMode() throws SQLException {
        Statement setSQLMode = getHub().getConnection().createStatement();
        setSQLMode.execute("set sql_mode := 'PIPES_AS_CONCAT'");
        setSQLMode.close();
    }

    public static class Factory implements EncryptedBusinessKey.Factory<DBEncryptedBusinessKey> {
        @Override
        public DBEncryptedBusinessKey construct(EncryptedHub<DBEncryptedBusinessKey> hub, Object... values) throws Exception {
            return new DBEncryptedBusinessKey(hub, values);
        }

        @Override
        public DBEncryptedBusinessKey construct(EncryptedHub<DBEncryptedBusinessKey> hub, String hashedEncryption, String hash, Object... values) {
            return new DBEncryptedBusinessKey(hub, hashedEncryption, hash, values);
        }
    }
}
