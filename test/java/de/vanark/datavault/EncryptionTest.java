package de.vanark.datavault;

import de.cimt.talendcomp.checksum.HashCalculation;
import org.junit.jupiter.api.Test;

import java.sql.*;
import java.util.StringJoiner;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionTest {
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