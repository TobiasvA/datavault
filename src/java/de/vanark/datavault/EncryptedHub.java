package de.vanark.datavault;

import de.cimt.talendcomp.checksum.NormalizeObjectConfig;

import java.lang.reflect.Constructor;
import java.sql.*;
import java.util.*;

public class EncryptedHub {
    final static String CYCLIC_REDUNDANCY_CHECK_ADDON = "1";

    private Map<String, Object> additionalColumnsHub;
    private Map<String, Object> additionalColumnsEks;
    private final Class<? extends EncryptedBusinessKey> businessKeyClass;
    private final Cache<Object[], EncryptedBusinessKey> cache = new Cache<>();
    private final Connection connection;
    private final String crcColumnEks;
    private final String encryptedHashColumnEks;
    private final String encryptedHashColumnHub;
    private final String encryptionKeyEks;
    private final String hashColumnEks;
    private final KeyConfig[] keyConfigs;
    private final String loadDateColumnEks;
    private final String loadDateColumnHub;
    private final String recordSourceColumnEks;
    private final String recordSourceColumnHub;
    private final String tableEks;
    private final String tableHub;

    public EncryptedHub(Connection connection, Class<? extends EncryptedBusinessKey> businessKeyClass,
                        String tableHub, String tableEks,
                        String loadDateColumnEks, String loadDateColumnHub,
                        String recordSourceColumnEks, String recordSourceColumnHub,
                        String hashColumnEks,
                        String encryptedHashColumnEks, String encryptedHashColumnHub,
                        String crcColumnEks,
                        String encryptionKeyEks,
                        KeyConfig... keyConfigs) {
        this.connection = connection;
        this.businessKeyClass = businessKeyClass;
        this.crcColumnEks = crcColumnEks;
        this.encryptedHashColumnEks = encryptedHashColumnEks;
        this.encryptedHashColumnHub = encryptedHashColumnHub;
        this.encryptionKeyEks = encryptionKeyEks;
        this.hashColumnEks = hashColumnEks;
        this.keyConfigs = keyConfigs;
        this.loadDateColumnEks = loadDateColumnEks;
        this.loadDateColumnHub = loadDateColumnHub;
        this.recordSourceColumnEks = recordSourceColumnEks;
        this.recordSourceColumnHub = recordSourceColumnHub;
        this.tableEks = tableEks;
        this.tableHub = tableHub;
    }

    public EncryptedHub addAdditionalColumnEks(String columnName, Object value) {
        if(additionalColumnsEks == null) additionalColumnsEks = new HashMap<>();
        additionalColumnsEks.put(columnName, value);
        return this;
    }

    public EncryptedHub addAdditionalColumnHub(String columnName, Object value) {
        if(additionalColumnsHub == null) additionalColumnsHub = new HashMap<>();
        additionalColumnsHub.put(columnName, value);
        return this;
    }

    public Map<String, Object> getAdditionalColumnsEks() {
        return additionalColumnsEks;
    }

    public Map<String, Object> getAdditionalColumnsHub() {
        return additionalColumnsHub;
    }

    public EncryptedBusinessKey getBusinessKey(Object... values) throws Exception {
        EncryptedBusinessKey businessKey = this.cache.get(values);
        if (businessKey == null) businessKey = queryBusinessKey(values);
        final Constructor<? extends EncryptedBusinessKey> constructor;
        constructor = businessKeyClass.getConstructor(EncryptedHub.class, Object[].class);
        if (businessKey == null) businessKey = constructor.newInstance(this, values);
        return businessKey;
    }

    public Connection getConnection() {
        return connection;
    }

    public String getCrcColumnEks() {
        return crcColumnEks;
    }

    public String getEncryptionKeyEks() {
        return encryptionKeyEks;
    }

    public String getEncryptedHashColumnEks() {
        return encryptedHashColumnEks;
    }

    public String getEncryptedHashColumnHub() {
        return encryptedHashColumnHub;
    }

    public String getHashColumnEks() {
        return hashColumnEks;
    }

    KeyConfig getKeyConfig(short index) {
        return keyConfigs[index];
    }

    private static String hash(Object[] values, NormalizeObjectConfig[] configs) {
        GlobalHashNormalization.DEFAULT_NORMALIZATION.reset();
        for (short i = 0; i < values.length; i++) {
            GlobalHashNormalization.DEFAULT_NORMALIZATION.add(values[i], configs[i]);
        }
        return GlobalHashNormalization.DEFAULT_NORMALIZATION.calculateHash(
                GlobalHashNormalization.DEFAULT_HASH_ALGORITHM,
                GlobalHashNormalization.DEFAULT_HASH_OUTPUT_ENCODING);
    }

    public String getLoadDateColumnEks() {
        return loadDateColumnEks;
    }

    public String getLoadDateColumnHub() {
        return loadDateColumnHub;
    }

    public String getRecordSourceColumnEks() {
        return recordSourceColumnEks;
    }

    public String getRecordSourceColumnHub() {
        return recordSourceColumnHub;
    }

    public short getSize() {
        return (short)keyConfigs.length;
    }

    public String getTableEks() {
        return tableEks;
    }

    public String getTableHub() {
        return tableHub;
    }

    String hash(Object... values) {
        return hash(values, keyConfigs);
    }

    private EncryptedBusinessKey queryBusinessKey(Object... values) throws Exception {
        final StringJoiner query = new StringJoiner("\n")
                .add("select "+encryptedHashColumnEks+", "+hashColumnEks)
                .add("from "+tableEks)
                .add("where "+hashColumnEks+" = ?");
        PreparedStatement statement = connection.prepareStatement(query.toString());
        String hashedValues = hash(values);
        statement.setString(1, hashedValues);
        ResultSet result;
        try {
            result = statement.executeQuery();
        } catch (SQLSyntaxErrorException exception) {
            System.err.println(query);
            System.err.println("1: "+hashedValues);
            throw exception;
        }
        Constructor<? extends EncryptedBusinessKey> constructor;
        constructor = businessKeyClass.getConstructor(EncryptedHub.class, String.class, String.class, Object[].class);
        EncryptedBusinessKey businessKey = result.next() ?
                constructor.newInstance(
                        this,
                        result.getString(encryptedHashColumnEks),
                        result.getString(hashColumnEks),
                        values)
                : null;
        result.close();
        statement.close();
        if (businessKey != null)
            cache.add(values, businessKey, 600000);
        return businessKey;
    }

    public static class KeyConfig extends NormalizeObjectConfig {

        private final String hubColumnName;
        private final boolean encrypted;

        public KeyConfig(String hubColumnName, boolean encrypted) {
            this(hubColumnName, encrypted, GlobalHashNormalization.DEFAULT_OBJECT_CONFIG);
        }

        public KeyConfig(String hubColumnName, boolean encrypted, NormalizeObjectConfig normalizeObjectConfig) {
            this(hubColumnName, encrypted, normalizeObjectConfig.getCaseSensitive().name(), normalizeObjectConfig.isTrimming());
        }

        public KeyConfig(String hubColumnName, boolean encrypted, String caseSensitive, boolean trimming) {
            super(caseSensitive, trimming);
            this.hubColumnName = hubColumnName;
            this.encrypted = encrypted;
        }

        public String getHubColumnName() {
            return hubColumnName;
        }

        public boolean isEncrypted() {
            return encrypted;
        }
    }


}