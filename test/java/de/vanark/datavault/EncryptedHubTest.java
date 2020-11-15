package de.vanark.datavault;

import org.junit.jupiter.api.*;

import java.sql.*;

class EncryptedHubTest {
    private Connection connection;
    private EncryptedHub<DBEncryptedBusinessKey> teilvertragHub;

    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection("jdbc:mariadb://localhost:3306/datavault?user=dvload&password=dvload");
        EncryptedHub.KeyConfig mandantAttribute = new EncryptedHub.KeyConfig("mandant", false);
        EncryptedHub.KeyConfig vertragAttribute = new EncryptedHub.KeyConfig("vertrag_ec", true);
        EncryptedHub.KeyConfig teilvertragAttribute = new EncryptedHub.KeyConfig("teilvertrag_ec", true);
        teilvertragHub = new EncryptedHub<>(
                connection, new DBEncryptedBusinessKey.Factory(),
                "teilvertrag_hub",
                "teilvertrag_hub_eks",
                "meta_loaddate",
                "meta_loaddate",
                "meta_recordsource",
                "meta_recordsource",
                "meta_hk_teilvertrag",
                "meta_hk_teilvertrag_ec",
                "meta_hk_teilvertrag_ec",
                "meta_hk_teilvertrag_crc",
                "meta_teilvertrag_hub_ek",
                mandantAttribute,
                vertragAttribute,
                teilvertragAttribute)
                .addAdditionalColumnEks("meta_jobinstanceid", 0)
                .addAdditionalColumnHub("meta_jobinstanceid", 0);
    }

    @AfterEach
    void tearDown() throws SQLException {
        connection.close();
    }

    @Test
    void getBusinessKey() throws Exception {
        long t = System.currentTimeMillis();
        long end = t+60000;
        int n = 0;
        while(System.currentTimeMillis() < end) {
            int mandant = (int) (Math.random() * 10);
            int vertrag = (int) (Math.random() * 1000000000);
            int teilvertrag = (int) (Math.random() * 10);
            teilvertragHub.getBusinessKey(mandant, vertrag, teilvertrag);
            n++;
        }
        System.out.println(n);
    }
}