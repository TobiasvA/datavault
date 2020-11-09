package de.vanark.datavault;

import org.junit.jupiter.api.*;

import java.sql.*;

class HubTest {
    private Connection connection;
    private Hub teilvertragHub;

    @BeforeEach
    void setUp() throws SQLException {
        connection = DriverManager.getConnection("jdbc:mariadb://localhost:3306/datavault?user=dvload&password=dvload");
        Hub.KeyConfig mandantAttribute = new Hub.KeyConfig("mandant", false);
        Hub.KeyConfig vertragAttribute = new Hub.KeyConfig("vertrag_ec", true);
        Hub.KeyConfig teilvertragAttribute = new Hub.KeyConfig("teilvertrag_ec", true);
        teilvertragHub = new Hub(
                connection,
                "hex(aes_encrypt({value}, {key}))",
                "sha2({value}, 256)",
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
        long end = t+600000;
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

    @Test
    void hashCollision() throws SQLException {
        int a1;
        int b1;
        int c1;
        String hkec1;
        long t = System.currentTimeMillis();
        long s = t;
        int n = 0;
        Statement setSQLMode = connection.createStatement();
        setSQLMode.execute("set sql_mode := 'PIPES_AS_CONCAT'");
        setSQLMode.close();
        String query = "select " +
                        "a1||'|'||hex(aes_encrypt(b1, enc))||'|'||hex(aes_encrypt(c1, enc)) ec1, " +
                        "sha2(a1||'|'||hex(aes_encrypt(b1, enc))||'|'||hex(aes_encrypt(c1, enc)), 256) hkec1 " +
                        "from (select ? a1, ? b1, ? c1, ? enc) t";
        PreparedStatement statement = connection.prepareStatement(query);
        Cache<String, String> cache = new Cache<>();
        do {
            a1 = (int) (Math.random() * 10);
            b1 = (int) (Math.random() * 1000000000);
            c1 = (int) (Math.random() * 10);
            String enc = Encryption.generateSecretKey();
            statement.setInt(1, a1);
            statement.setInt(2, b1);
            statement.setInt(3, c1);
            statement.setString(4, enc);
            ResultSet result = statement.executeQuery();
            result.next();
            String ec1 = result.getString(1);
            hkec1 = result.getString(2);
            result.close();
            statement.clearParameters();
            n++;
            String ec2 = cache.get(hkec1);
            if (ec2 != null) {
                break;
            }
            cache.add(hkec1, ec1, 600000);
            if (System.currentTimeMillis() - t > 10000) {
                System.out.println(n + " " + cache.size());
                t = System.currentTimeMillis();
            }
        } while (System.currentTimeMillis() - s < 600000);

    }
}