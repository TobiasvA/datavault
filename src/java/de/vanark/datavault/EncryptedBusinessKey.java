package de.vanark.datavault;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLSyntaxErrorException;
import java.time.LocalDateTime;
import java.util.LinkedList;
import java.util.Map;
import java.util.StringJoiner;

public abstract class EncryptedBusinessKey {
    private String cyclicRedundancyCheck;
    private String encryptionKey;
    private final String hash;
    private final EncryptedHub hub;
    private String hashedEncryption;
    private final Object[] values;

    public EncryptedBusinessKey(EncryptedHub hub, Object... values) throws Exception {
        this.hub = hub;
        this.hash = hub.hash(values);
        GlobalHashNormalization.DEFAULT_NORMALIZATION.add(
                EncryptedHub.CYCLIC_REDUNDANCY_CHECK_ADDON,
                GlobalHashNormalization.DEFAULT_OBJECT_CONFIG);
        this.cyclicRedundancyCheck = GlobalHashNormalization.DEFAULT_NORMALIZATION.calculateHash(
                GlobalHashNormalization.DEFAULT_HASH_ALGORITHM,
                GlobalHashNormalization.DEFAULT_HASH_OUTPUT_ENCODING);
        this.values = values;
        LocalDateTime loadDate = LocalDateTime.now();
        Connection connection = hub.getConnection();
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            persistHub(loadDate);
            persistEks(loadDate);
        } catch(SQLException sqlException) {
            connection.rollback();
            throw sqlException;
        }
        connection.commit();
        connection.setAutoCommit(autoCommit);
    }

    public EncryptedBusinessKey(EncryptedHub hub, String hashedEncryption, String hash, Object... values) {
        this.hub = hub;
        this.hashedEncryption = hashedEncryption;
        this.hash = hash;
        this.values = values;
    }

    abstract String getEncryptedValue(short index) throws SQLException;

    String getEncryptionKey() {
        if (encryptionKey == null )
            encryptionKey = Encryption.generateSecretKey();
        return encryptionKey;
    }

    String getHashedEncryption() throws SQLException {
        return hashedEncryption;
    }

    EncryptedHub getHub() {
        return hub;
    }

    Object getValue(short index) {
        return values[index];
    }

    private void persistEks(LocalDateTime loadDate) throws SQLException {
        final StringJoiner columnList = new StringJoiner(", ")
                .add(hub.getLoadDateColumnEks())
                .add(hub.getRecordSourceColumnEks())
                .add(hub.getHashColumnEks())
                .add(hub.getEncryptedHashColumnEks())
                .add(hub.getCrcColumnEks())
                .add(hub.getEncryptionKeyEks());

        final LinkedList<Object> valueList = new LinkedList<>();
        valueList.add(loadDate);
        valueList.add(this.getClass().getCanonicalName().substring(0, 27));
        valueList.add(hash);
        valueList.add(getHashedEncryption());
        valueList.add(cyclicRedundancyCheck);
        valueList.add(getEncryptionKey());

        if (hub.getAdditionalColumnsEks() != null)
            for (Map.Entry<String, Object> entry : hub.getAdditionalColumnsEks().entrySet()) {
                columnList.add(entry.getKey());
                valueList.add(entry.getValue());
            }

        final StringJoiner parameter = new StringJoiner(", ");
        valueList.stream().map(value -> "?").forEach(parameter::add);
        StringJoiner insertSQL = new StringJoiner("\n")
                .add("insert into "+ hub.getTableEks() +"("+columnList+")")
                .add("values("+parameter+")");

        final PreparedStatement statement = hub.getConnection().prepareStatement(insertSQL.toString());
        for (int i = 0; i < valueList.size(); i++)
            statement.setObject(i + 1, valueList.get(i));
        try {
            statement.executeUpdate();
        } catch (SQLSyntaxErrorException exception) {
            System.err.println(insertSQL);
            for (int index = 0; index < valueList.size(); index++) {
                System.err.println(index + ": " + valueList.get(index));
            }
            throw exception;
        }
        statement.close();
    }

    private void persistHub(LocalDateTime loadDate) throws SQLException {
        final StringJoiner columnList = new StringJoiner(", ")
                .add(hub.getLoadDateColumnHub())
                .add(hub.getRecordSourceColumnHub())
                .add(hub.getEncryptedHashColumnHub());

        final LinkedList<Object> valueList = new LinkedList<>();
        valueList.add(loadDate);
        valueList.add(this.getClass().getCanonicalName().substring(0, 27));
        valueList.add(getHashedEncryption());
        for (short i = 0; i < hub.getSize(); i++) {
            columnList.add(hub.getKeyConfig(i).getHubColumnName());
            valueList.add((hub.getKeyConfig(i).isEncrypted()) ? getEncryptedValue(i) : getValue(i));
        }

        if (hub.getAdditionalColumnsHub() != null)
            for (Map.Entry<String, Object> entry : hub.getAdditionalColumnsHub().entrySet()) {
                columnList.add(entry.getKey());
                valueList.add(entry.getValue());
            }

        final StringJoiner parameter = new StringJoiner(", ");
        valueList.stream().map(value -> "?").forEach(parameter::add);
        StringJoiner insertSQL = new StringJoiner("\n")
                .add("insert into "+ hub.getTableHub() +"("+columnList+")")
                .add("values("+parameter+")");

        final PreparedStatement statement = hub.getConnection().prepareStatement(insertSQL.toString());
        for (int i = 0; i < valueList.size(); i++)
            statement.setObject(i + 1, valueList.get(i));
        try {
            statement.executeUpdate();
        } catch (SQLSyntaxErrorException exception) {
            System.err.println(insertSQL);
            for (int index = 0; index < valueList.size(); index++) {
                System.err.println(index + ": " + valueList.get(index));
            }
            throw exception;
        }
        statement.close();
    }

    EncryptedBusinessKey setHashedEncryption(String hashedEncryption) {
        this.hashedEncryption = hashedEncryption;
        return this;
    }
}
