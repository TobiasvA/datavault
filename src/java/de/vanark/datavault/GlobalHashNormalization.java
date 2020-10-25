package de.vanark.datavault;

import de.cimt.talendcomp.checksum.HashCalculation;
import de.cimt.talendcomp.checksum.HashNormalization;
import de.cimt.talendcomp.checksum.NormalizeConfig;
import de.cimt.talendcomp.checksum.NormalizeObjectConfig;

public class GlobalHashNormalization {
    public final static NormalizeConfig DEFAULT_CONFIG = new NormalizeConfig(
            "|",
            "",
            false,
            "\"",
            "yyyyMMdd",
            "ENGLISH",
            7,
            15,
            true,
            "000000000000000000000000",
            true,
            false);
    public final static String DEFAULT_HASH_ALGORITHM = "SHA1";
    public final static HashCalculation.HASH_OUTPUT_ENCODINGS DEFAULT_HASH_OUTPUT_ENCODING =
            HashCalculation.HASH_OUTPUT_ENCODINGS.BASE64;
    public final static HashNormalization DEFAULT_NORMALIZATION = new HashNormalization(DEFAULT_CONFIG);
    public final static NormalizeObjectConfig DEFAULT_OBJECT_CONFIG =
            new NormalizeObjectConfig(NormalizeObjectConfig.CaseSensitive.CASE_SENSITIVE.name(), false);
}
