package de.vanark.datavault;

import de.cimt.talendcomp.checksum.NormalizeObjectConfig;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;

public class Hub {
    private final static String CYCLIC_REDUNDANCY_CHECK_ADDON = "1";

    private Map<String, Object> additionalColumnsHub;
    private Map<String, Object> additionalColumnsEks;
    private final Cache<Object[], BusinessKey> cache = new Cache<>();
    private final Connection connection;
    private final String crcColumnEks;
    private final String encryptedHashColumnEks;
    private final String encryptedHashColumnHub;
    private final String encryptionKeyEks;
    private final String encryptionFunction;
    private final String hashColumnEks;
    private final String hashFunction;
    private final KeyConfig[] keyConfigs;
    private final String loadDateColumnEks;
    private final String loadDateColumnHub;
    private final String recordSourceColumnEks;
    private final String recordSourceColumnHub;
    private final String tableEks;
    private final String tableHub;

    public Hub(Connection connection, String encryptionFunction, String hashFunction,
               String tableHub, String tableEks,
               String loadDateColumnEks, String loadDateColumnHub,
               String recordSourceColumnEks, String recordSourceColumnHub,
               String hashColumnEks,
               String encryptedHashColumnEks, String encryptedHashColumnHub,
               String crcColumnEks,
               String encryptionKeyEks,
               KeyConfig... keyConfigs) {
        this.connection = connection;
        this.encryptionFunction = encryptionFunction;
        this.hashFunction = hashFunction;
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

    private KeyConfig getKeyConfig(short index) {
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
    }

    public class BusinessKey {
        private String cyclicRedundancyCheck;
        private String encryptionKey;
        private String[] encryptedValues;
        private final String hash;
        private String hashedEncryption;
        private String[] normalizedValues;
        private final Object[] values;

        private BusinessKey(Object... values) throws Exception {
            this.hash = hash(values);
            GlobalHashNormalization.DEFAULT_NORMALIZATION.add(
                    CYCLIC_REDUNDANCY_CHECK_ADDON,
                    GlobalHashNormalization.DEFAULT_OBJECT_CONFIG);
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

        private String buildEncryptionCall(short index) {
            return encryptionFunction
                    .replace("{key}", "'" + getEncryptionKey() + "'")
                    .replace("{value}", "'" + getNormalizedValue(index) + "'");
        }

        private String buildHashEncryptionCall() {
            final StringJoiner value = new StringJoiner(GlobalHashNormalization.DEFAULT_CONFIG.getDelimter());
            for (short i = 0; i < keyConfigs.length; i++) {
                value.add((getKeyConfig(i).encrypted) ? buildEncryptionCall(i) : getNormalizedValue(i));
            }
            return hashFunction
                    .replace("{value}", value.toString());
        }

        private void encrypt() throws SQLException {
            encryptedValues = new String[values.length];
            final StringJoiner selections = new StringJoiner(", ")
                    .add(buildHashEncryptionCall());
            for (short index = 0; index < values.length; index++)
                if (keyConfigs[index].encrypted)
                    selections.add(buildEncryptionCall(index));
                else
                    selections.add("null");
            String query = "select " + selections.toString();
            Statement statement = connection.createStatement();
            ResultSet result = statement.executeQuery(query);
            result.next();
            hashedEncryption = result.getString(1);
            for (short index = 0; index < values.length; index++)
                if (keyConfigs[index].encrypted)
                    encryptedValues[index] = result.getString(index + 2);
            result.close();
            statement.close();

            /* local encryption
            encryptionKey = Encryption.generateSecretKey();
            encryptedValues = new String[values.length];
            Object[] encryptedKeyValues = new Object[values.length];
            NormalizeObjectConfig[] configs = new NormalizeObjectConfig[values.length];
            for (int i = 0; i < values.length; i++)
                if (keyConfigs[i].encrypted) {
                    encryptedValues[i] = Encryption.encrypt(encryptionKey, values[i]);
                    encryptedKeyValues[i] = encryptedValues[i];
                    configs[i] = keyConfigs[i];
                } else {
                    encryptedKeyValues[i] = values[i];
                    configs[i] = GlobalHashNormalization.DEFAULT_OBJECT_CONFIG;
                }
            hashedEncryption = hash(encryptedKeyValues, configs);*/
        }

        private String getEncryptedValue(short index) {
            return encryptedValues[index];
        }

        private String getEncryptionKey() {
            if (encryptionKey == null )
                encryptionKey = Encryption.generateSecretKey();
            return encryptionKey;
        }

        private String getNormalizedValue(short index) {
            if (normalizedValues == null)
                normalizedValues = new String[values.length];
            if (normalizedValues[index] == null) {
                GlobalHashNormalization.DEFAULT_NORMALIZATION.reset();
                GlobalHashNormalization.DEFAULT_NORMALIZATION.add(getValue(index), getKeyConfig(index));
                normalizedValues[index] = GlobalHashNormalization.DEFAULT_NORMALIZATION.getNormalizedString();
            }
            return normalizedValues[index];
        }

        private Object getValue(short index) {
            return values[index];
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
            valueList.add(getEncryptionKey());

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
                    .add(loadDateColumnHub)
                    .add(recordSourceColumnHub)
                    .add(encryptedHashColumnHub);

            final LinkedList<Object> valueList = new LinkedList<>();
            valueList.add(loadDate);
            valueList.add(this.getClass().getCanonicalName().substring(0, 27));
            valueList.add(hashedEncryption);
            for (short i = 0; i < keyConfigs.length; i++) {
                columnList.add(getKeyConfig(i).hubColumnName);
                valueList.add((getKeyConfig(i).encrypted) ? getEncryptedValue(i) : getValue(i));
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
    }
}