package de.vanark.datavault;

import org.junit.jupiter.api.*;

import java.sql.*;

import static org.junit.jupiter.api.Assertions.*;

class HubTest {
    private Connection connection;
    private Hub teilvertrag;

    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection("jdbc:mariadb://localhost:3306/datavault?user=dvload&password=dvload");
        Hub.KeyConfig mandantAttribute = new Hub.KeyConfig("mandant", false);
        Hub.KeyConfig vertragAttribute = new Hub.KeyConfig("vertrag_ec", true);
        Hub.KeyConfig teilvertragAttribute = new Hub.KeyConfig("teilvertrag_ec", true);
        teilvertrag = new Hub(
                connection,
                "aes_encrypt({value}, {key})",
                "sha1({value})",
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
        Hub.BusinessKey businessKey = teilvertrag.getBusinessKey(1, 4711, 1);
    }

    /*@Test
    public void crypt() throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:mariadb://localhost:3306/datavault?user=dvload&password=dvload");
        Statement statement2 = connection.createStatement();
        ResultSet result2 = statement2.executeQuery("select aes_encrypt('12345', '"+getEncryptionKey()+"')");
        result2.next();
        System.out.println("2: " + result2.getString(1));
        result2.close();
        statement2.close();

        Statement statement3 = connection.createStatement();
        ResultSet result3 = statement3.executeQuery("select aes_decrypt('"+encryptedValues[1]+"', '"+getEncryptionKey()+"')");
        result3.next();
        System.out.println("3: " + result3.getString(1));
        result3.close();
        statement3.close();

        Statement statement4 = connection.createStatement();
        ResultSet result4 = statement4.executeQuery("select aes_decrypt(aes_encrypt('"+values[1]+"', '"+getEncryptionKey()+"'), '"+getEncryptionKey()+"')");
        result4.next();
        System.out.println("4: " + result4.getString(1));
        result4.close();
        statement4.close();
    }*/
}