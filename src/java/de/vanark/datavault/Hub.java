package de.vanark.datavault;

import de.cimt.talendcomp.checksum.NormalizeObjectConfig;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;

public class Hub {
    private final static String CYCLIC_REDUNDANCY_CHECK_ADDON = "1";

    private final Cache<Object[], BusinessKey> cache = new Cache<>();
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
    private Map<String, Object> additionalColumnsHub;
    private Map<String, Object> additionalColumnsEks;

    public Hub(Connection connection, String tableHub, String tableEks,
               String loadDateColumnEks, String loadDateColumnHub,
               String recordSourceColumnEks, String recordSourceColumnHub,
               String hashColumnEks,
               String encryptedHashColumnEks, String encryptedHashColumnHub,
               String crcColumnEks,
               String encryptionKeyEks,
               KeyConfig... keyConfigs) {
        this.connection = connection;
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

    public Hub addAdditionalColumnEks(String columnName, Object value) {
        if(additionalColumnsEks == null) additionalColumnsEks = new HashMap<>();
        additionalColumnsEks.put(columnName, value);
        return this;
    }

    public Hub addAdditionalColumnHub(String columnName, Object value) {
        if(additionalColumnsHub == null) additionalColumnsHub = new HashMap<>();
        additionalColumnsHub.put(columnName, value);
        return this;
    }

    public BusinessKey getBusinessKey(Object... values) throws Exception {
        BusinessKey businessKey = this.cache.get(values);
        if (businessKey == null) businessKey = queryBusinessKey();
        if (businessKey == null) businessKey = new BusinessKey(values);
        return businessKey;
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

    private String hash(Object... values) {
        return hash(values, keyConfigs);
    }

    private BusinessKey queryBusinessKey(Object... values) throws Exception {
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
        BusinessKey businessKey = result.next() ?
                new BusinessKey(
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
        private final static NormalizeObjectConfig DEFAULT_OBJECT_CONFIG =
                new NormalizeObjectConfig(NormalizeObjectConfig.CaseSensitive.CASE_SENSITIVE.name(), false);

        private final String hubColumnName;
        private final boolean encrypted;

        public KeyConfig(String hubColumnName, boolean encrypted) {
            this(hubColumnName, encrypted, DEFAULT_OBJECT_CONFIG);
        }

        public KeyConfig(String hubColumnName, boolean encrypted, NormalizeObjectConfig normalizeObjectConfig) {
            this(hubColumnName, encrypted, normalizeObjectConfig.getCaseSensitive().name(), normalizeObjectConfig.isTrimming());
        }

        public KeyConfig(String hubColumnName, boolean encrypted, String caseSensitive, boolean trimming) {
            super(caseSensitive, trimming);
            this.hubColumnName = hubColumnName;
            this.encrypted = encrypted;
        }
    }

    public class BusinessKey {
        private String cyclicRedundancyCheck;
        private final String hash;
        private String hashedEncryption;
        private final Object[] values;
        private String base64Key;
        private String[] encryptedValues;

        private BusinessKey(Object... values) throws Exception {
            this.hash = hash(values);
            GlobalHashNormalization.DEFAULT_NORMALIZATION.add(CYCLIC_REDUNDANCY_CHECK_ADDON, KeyConfig.DEFAULT_OBJECT_CONFIG);
            this.cyclicRedundancyCheck = GlobalHashNormalization.DEFAULT_NORMALIZATION.calculateHash(
                    GlobalHashNormalization.DEFAULT_HASH_ALGORITHM,
                    GlobalHashNormalization.DEFAULT_HASH_OUTPUT_ENCODING);
            this.values = values;
            encrypt();
            LocalDateTime loadDate = LocalDateTime.now();
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

        private BusinessKey(String hashedEncryption, String hash, Object... values) {
            this.hashedEncryption = hashedEncryption;
            this.hash = hash;
            this.values = values;
        }

        private void encrypt() throws Exception {
            base64Key = AesEncryption.generateBase64Key();
            encryptedValues = new String[values.length];
            Object[] encryptedKeyValues = new Object[values.length];
            NormalizeObjectConfig[] configs = new NormalizeObjectConfig[values.length];
            for (int i = 0; i < values.length; i++)
                if (keyConfigs[i].encrypted) {
                    encryptedValues[i] = AesEncryption.encrypt(values[i], base64Key);
                    encryptedKeyValues[i] = encryptedValues[i];
                    configs[i] = keyConfigs[i];
                } else {
                    encryptedKeyValues[i] = values[i];
                    configs[i] = KeyConfig.DEFAULT_OBJECT_CONFIG;
                }
            hashedEncryption = hash(encryptedKeyValues, configs);
        }

        private void persistEks(LocalDateTime loadDate) throws SQLException {
            final StringJoiner columnList = new StringJoiner(", ")
                    .add(loadDateColumnEks)
                    .add(recordSourceColumnEks)
                    .add(hashColumnEks)
                    .add(encryptedHashColumnEks)
                    .add(crcColumnEks)
                    .add(encryptionKeyEks);

            final LinkedList<Object> valueList = new LinkedList<>();
            valueList.add(loadDate);
            valueList.add(this.getClass().getCanonicalName().substring(0, 27));
            valueList.add(hash);
            valueList.add(hashedEncryption);
            valueList.add(cyclicRedundancyCheck);
            valueList.add(base64Key);

            if (additionalColumnsEks != null)
                for (Map.Entry<String, Object> entry : additionalColumnsEks.entrySet()) {
                    columnList.add(entry.getKey());
                    valueList.add(entry.getValue());
                }

            final StringJoiner parameter = new StringJoiner(", ");
            valueList.stream().map(value -> "?").forEach(parameter::add);
            StringJoiner insertSQL = new StringJoiner("\n")
                    .add("insert into "+ tableEks +"("+columnList+")")
                    .add("values("+parameter+")");

            final PreparedStatement statement = connection.prepareStatement(insertSQL.toString());
            for (int i = 0; i < valueList.size(); i++)
                statement.setObject(i + 1, valueList.get(i));
            statement.executeUpdate();
            statement.close();
        }

        private void persistHub(LocalDateTime loadDate) throws SQLException {
            final StringJoiner columnList = new StringJoiner(", ")
                    .add(loadDateColumnHub)
                    .add(recordSourceColumnHub)
                    .add(encryptedHashColumnHub);

            final LinkedList<Object> valueList = new LinkedList<>();
            valueList.add(loadDate);
            valueList.add(this.getClass().getCanonicalName().substring(0, 27));
            valueList.add(hashedEncryption);
            for (short i = 0; i < keyConfigs.length; i++) {
                columnList.add(keyConfigs[i].hubColumnName);
                valueList.add((keyConfigs[i].encrypted) ? encryptedValues[i] : values[i]);
            }

            if (additionalColumnsHub != null)
                for (Map.Entry<String, Object> entry : additionalColumnsHub.entrySet()) {
                    columnList.add(entry.getKey());
                    valueList.add(entry.getValue());
                }

            final StringJoiner parameter = new StringJoiner(", ");
            valueList.stream().map(value -> "?").forEach(parameter::add);
            StringJoiner insertSQL = new StringJoiner("\n")
                    .add("insert into "+ tableHub +"("+columnList+")")
                    .add("values("+parameter+")");

            final PreparedStatement statement = connection.prepareStatement(insertSQL.toString());
            for (int i = 0; i < valueList.size(); i++)
                statement.setObject(i + 1, valueList.get(i));
            statement.executeUpdate();
            statement.close();
        }
    }
}
