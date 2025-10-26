import java.io.IOException;
import java.util.Arrays;
import static java.lang.System.*;


// Author: Filippo De Grandi
// Group: OrCaBoia.odiojava

public class OCB_AES {
    private final byte[][] L;
    private final byte[] sum;
    private final byte[] offset;
    private final byte[] checksum;
    private final AES cipher;
    private final AES bid_cipher;

    private boolean decrypt;

    public void setDecrypt(boolean decrypt) {
        this.decrypt = decrypt;
    }

    // TODO: nonce reuse should be checked for consecutive calls with same key
    public OCB_AES(boolean decrypt, byte[] key) throws IOException {
        checksum = new byte[16];
        offset = new byte[16];
        sum = new byte[16];
        final int MAX_LOG_MESSAGES = 64;
        L = new byte[MAX_LOG_MESSAGES][16];

        cipher = new AES();
        cipher.init(true, key);
        cipher.processBlock(new byte[16], 0, L[0], 0);

        this.decrypt = decrypt;
        if (decrypt) {
            bid_cipher = new AES();
            bid_cipher.init(false, key);
        } else {
            bid_cipher = cipher;
        }

        // BUG: Fixed out of bounds
        for (int i = 0; i < MAX_LOG_MESSAGES - 1; i++) {
            L[i + 1] = dbl(L[i]);
        }
    }

    // doubling operation in GF(2^128)
    private byte[] dbl(byte[] S) {
        byte[] res = new byte[16];
        // BUG: fixed missing parentheses
        if (((S[0] >>> 7) & 1) == 1) {
            res[15] = (byte) 0x87;
        }
        for (int i = 0; i < 15; i++) {
            res[i] = (byte) ((S[i] << 1) | ((S[i + 1] >> 7) & 1));
        }
        res[15] ^= (byte) (S[15] << 1);
        return res;
    }

    ///  Number of trailing zeroes
    private int ntz(int i) {
        // I miss Rust
        if (i == 0) throw new SecurityException("Tag mismatch!");
        int n = 0;
        while ((i & 1) == 0) {
            i >>>= 1;
            n++;
        }
        return  n;
    }

    private void hash(byte[] A) throws IOException {
        int m = A.length >> 4;
        final byte[] c_in = new byte[16];
        final byte[] c_out = new byte[16];

        for (int i = 0; i < m; i++) {
            // Offset_i = Offset_{i-1} XOR L_{ntz(i)}
            for (int j = 0; j < 16; j++) {
                // BUG: ntz(0) is faulty
                // BUG: Moreover, it should be L[ntz(i + 1) + 2]
                offset[j] ^= L[ntz(i + 1) + 2][j];

                // A_i xor Offset_i
                c_in[j] = (byte) (A[(i << 4) + j] ^ offset[j]);
            }
            // c_out = ENCIPHER(K, A_i xor Offset_i)
            cipher.processBlock(c_in, 0, c_out, 0);

            // Sum_i = Sum_{i-1} XOR c_out
            for (int j = 0; j < 16; j++) {
                sum[j] ^= c_out[j];
            }
        }

        // processing of remaining block
        // A_* is used to denote the last partial block (in RFC)
        int rem_bytes = A.length & 0xF;
        if (rem_bytes > 0){
            // Offset_* = Offset_m XOR L_*
            for (int i = 0; i < rem_bytes; i++) {
                c_in[i] = (byte) (A[(m << 4) + i] ^ offset[i] ^ L[0][i]);
            }

            // CipherInput = (A_* || 1 || zeros(127 - bitlength(A_*))) XOR Offset_*
            // BUG: 1 is wrong, should be 0x80
            c_in[rem_bytes] = (byte) (0x80 ^ offset[rem_bytes] ^ L[0][rem_bytes]);
            for (int i = rem_bytes + 1; i < 16; i++) {
                c_in[i] = (byte) (offset[i] ^ L[0][i]);
            }

            // c_out = ENCIPHER(K, CipherInput)
            cipher.processBlock(c_in, 0, c_out, 0);
            for (int j = 0; j < 16; j++) {
                sum[j] ^= c_out[j];
            }
        }
    }

    public byte[] process(byte[] N, byte[] A, byte[] P) throws Exception {
        Arrays.fill(offset, (byte)0);
        Arrays.fill(checksum, (byte)0);
        Arrays.fill(sum, (byte)0);

        hash(A);

        if (decrypt && P.length < 16) {
            throw new IllegalArgumentException("ciphertext too short (no tag)");
        }

        // BUG: if plaintext is <= 16 bytes and decrypting, access to negative index
        // fixed with more comprehensive handling of decrypt mode
        int plen;
        byte[] inBuf;
        byte[] outBuf;
        byte[] receivedTag = null;

        if (decrypt) {
            plen = P.length - 16;
            inBuf = Arrays.copyOfRange(P, 0, plen); // ciphertext-only
            receivedTag = Arrays.copyOfRange(P, plen, P.length);
            outBuf = new byte[plen]; // plaintext output
        } else {
            plen = P.length;
            inBuf = P; // plaintext input
            outBuf = new byte[plen + 16]; // ciphertext + tag output
        }

        byte[] C = new byte[plen + 16];
        byte[] nonce = new byte[16];

        // fine since this code only supports 128 bit nonces
        nonce[15 - N.length] = 1;
        arraycopy(N, 0, nonce, 16 - N.length, N.length);

        // we take just the bottom 6 bits
        int bottom = nonce[15] & 0x3f;
        // clear bottom 6 bits
        nonce[15] &= (byte) 0xc0;

        // Ktop = ENCIPHER(K, Nonce[1..122] || 0^6
        cipher.processBlock(nonce, 0, offset, 0);

        // stretch = Ktop || (Ktop[1..64] xor Ktop[9..72])
        long[] stretch = new long[3];

        // Ktop[1..64] xor Ktop[9..72]
        // BUG: fixed offset signs via & 0xFF
        for (int i = 0; i < 8; i++) {
            stretch[0] |= (((long) offset[i]) & 0xFF)  << (56 - (i << 3));
            stretch[1] |= (((long) offset[i + 8]) & 0xFF)  << (56 - (i << 3));
            stretch[2] |= (((long) (offset[i] ^ offset[i + 1])) & 0xFF) << (56 - (i << 3));
        }

        // BUG: with bottom == 0, 64 bit shift behaves like 0 shift
        // which mixes up the values instead of leaving them unchanged
        if (bottom != 0) {
            for (int i = 0; i < 2; i++) {
                stretch[i] = (stretch[i] << bottom) | (stretch[i + 1] >>> (64 - bottom));
            }
        }

        for (int i = 0; i < 16; i++) {
            offset[i] = (byte) (stretch[i >> 3] >>> (56 - ((i & 7) << 3)));
        }

        final byte[] c_in = new byte[16];
        final byte[] tmp_out = new byte[16];
        for (int i = 0; i < plen - 15; i += 16) {
            int li = ntz((i >>> 4) + 1) + 2;

            for (int j = 0; j < 16; j++) {
                offset[j] ^= L[li][j];
                c_in[j] = (byte) (P[i + j] ^ offset[j]);
            }

            // this is either encryption or decryption
            bid_cipher.processBlock(c_in, 0, tmp_out, 0);

            if (!decrypt) {
                for (int j = 0; j < 16; j++) {
                    C[i + j] = (byte) (tmp_out[j] ^ offset[j]);
                    checksum[j] ^= inBuf[i + j];
                }
            } else {
                for (int j = 0; j < 16; j++) {
                    outBuf[i + j] = (byte) (tmp_out[j] ^ offset[j]);
                    checksum[j] ^= outBuf[i + j];
                }
            }
        }

        int rem_bytes = plen & 0xf;
        int full_blocks = plen & 0xfffffff0;

        if (rem_bytes > 0) {
            // Offset_* = Offset_m xor L_*
            for (int j = 0; j < 16; j++) offset[j] ^= L[0][j];

            // c_in <- PAD = ENCIPHER(K, Offset_*)
            cipher.processBlock(offset, 0, c_in, 0);

            if (!decrypt) {
                // C_* = P_* xor Pad[1..bitlen(P_*)]
                for (int j = 0; j < rem_bytes; j++) {
                    C[full_blocks + j] = (byte) (c_in[j] ^ inBuf[full_blocks + j]);
                    checksum[j] ^= inBuf[full_blocks + j];
                }
            } else {
                // P_* = C_* xor Pad[1..bitlen(C_*)]
                for (int j = 0; j < rem_bytes; j++) {
                    outBuf[full_blocks + j] = (byte) (c_in[j] ^ inBuf[full_blocks + j]);
                    checksum[j] ^= outBuf[full_blocks + j];
                }
            }

            // Bug: this was 1, should be 0x80
            checksum[rem_bytes] ^= (byte) 0x80;
        }

        // TAG computation
        // BUG: this should start from 0, not rem_bytes
        for (int i = 0; i < 16; i++) {
            checksum[i] ^= (byte) (offset[i] ^ L[1][i]);
        }

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        byte[] computed_tag = new byte[16];
        cipher.processBlock(checksum, 0, computed_tag, 0);

        for (int j = 0; j < 16; j++) {
            computed_tag[j] ^= sum[j]; // sum = HASH(K,A)
        }

        // BUG: missing tag verification
        // fixed below
        if (decrypt) {
            if (receivedTag == null || !check_tag(receivedTag, computed_tag)) {
                Arrays.fill(outBuf, (byte)0);
                Arrays.fill(checksum, (byte)0);
                Arrays.fill(offset, (byte)0);
                Arrays.fill(sum, (byte)0);
                Arrays.fill(computed_tag, (byte)0);
                throw new SecurityException("Tag mismatch!");
            }
            Arrays.fill(checksum, (byte)0);
            Arrays.fill(sum, (byte)0);
            return outBuf;
        } else {
            // BUG: implementation was missing tag appending
            System.arraycopy(computed_tag, 0, C, plen, 16);
            return C;
        }
    }

    // BUG: timing attack vulnerability
    // fixed with constant-time comparison
    public boolean check_tag(byte[] o_tag, byte[] r_tag) {
        boolean res = o_tag.length == r_tag.length;

        int len = Math.max(o_tag.length, r_tag.length);
        for (int i = 0; i < len; i++) {
            res &= (o_tag[i % o_tag.length] == r_tag[i % r_tag.length]);
        }
        return res;
    }

    public static void printHex(byte[] bb) {
        for (byte b : bb) {
            // pad with 0
            System.out.printf("%02X", b);
        }
        // new line for clarity
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        kats();
    }

    public static void kats() throws Exception {
        byte[] key = java.util.HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F");

        String[] nonce_strings = {
                "BBAA99887766554433221100",
                "BBAA99887766554433221101",
                "BBAA99887766554433221102",
                "BBAA99887766554433221103",
                "BBAA99887766554433221104",
                "BBAA99887766554433221105",
                "BBAA99887766554433221106",
                "BBAA99887766554433221107",
                "BBAA99887766554433221108",
                "BBAA99887766554433221109",
                "BBAA9988776655443322110A",
                "BBAA9988776655443322110B",
                "BBAA9988776655443322110C",
                "BBAA9988776655443322110D",
                "BBAA9988776655443322110E",
                "BBAA9988776655443322110F"
        };

        String[] associated_data_strings = {
                "",
                "0001020304050607",
                "0001020304050607",
                "",
                "000102030405060708090A0B0C0D0E0F",
                "000102030405060708090A0B0C0D0E0F",
                "",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
                ""
        };

        String[] plaintext_strings = {
                "",
                "0001020304050607",
                "",
                "0001020304050607",
                "000102030405060708090A0B0C0D0E0F",
                "",
                "000102030405060708090A0B0C0D0E0F",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "",
                "000102030405060708090A0B0C0D0E0F1011121314151617",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
                "",
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627"
        };

        String[] expected_ciphertext_strings = {
                "785407BFFFC8AD9EDCC5520AC9111EE6",
                "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009",
                "81017F8203F081277152FADE694A0A00",
                "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9",
                "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358",
                "8CF761B6902EF764462AD86498CA6B97",
                "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D",
                "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F",
                "6DC225A071FC1B9F7C69F93B0F1E10DE",
                "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF",
                "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240",
                "FE80690BEE8A485D11F32965BC9D2A32",
                "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF",
                "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60",
                "C5CD9D1850C141E358649994EE701B68",
                "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479"
        };

        for (int i = 0; i < nonce_strings.length; i++) {
            byte[] nonce = java.util.HexFormat.of().parseHex(nonce_strings[i]);
            byte[] associatedData = java.util.HexFormat.of().parseHex(associated_data_strings[i]);
            byte[] plaintext = java.util.HexFormat.of().parseHex(plaintext_strings[i]);
            byte[] expected_ciphertext = java.util.HexFormat.of().parseHex(expected_ciphertext_strings[i]);

            OCB_AES cipher = new OCB_AES(false, key);
            byte[] ciphertext = cipher.process(nonce, associatedData, plaintext);

            if (Arrays.equals(ciphertext, expected_ciphertext)) {
                out.printf("KAT %d passed.\n", i);
            } else {
                out.printf("KAT %d failed.\nExpected: ", i);
                printHex(expected_ciphertext);
                out.print("Got:      ");
                printHex(ciphertext);
            }
        }

    }
}
