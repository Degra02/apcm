import java.io.IOException;

import static java.lang.System.*;

public class OCB_AES {
    private final byte[][] L;
    // Add L_* and L_dollar for ease of use
    private final byte[] L_ast;
    private final byte[] L_dollar;

    private final byte[] sum;
    private final byte[] offset;
    private final byte[] checksum;
    private final AES cipher;
    private final AES bid_cipher;
    private final boolean decrypt;

    public OCB_AES(boolean decrypt, byte[] key) throws IOException {
        checksum = new byte[16];
        offset = new byte[16];
        sum = new byte[16];
        final int MAX_LOG_MESSAGES = 64;
        L = new byte[MAX_LOG_MESSAGES][16];
        L_ast = new byte[16];

        cipher = new AES();
        cipher.init(true, key);
        cipher.processBlock(new byte[16], 0, L_ast, 0);

        this.decrypt = decrypt;
        if (decrypt) {
            bid_cipher = new AES();
            bid_cipher.init(false, key);
        } else {
            bid_cipher = cipher;
        }

        // BUG: Fixed out of bounds
        L_dollar = dbl(L_ast);
        L[0] = dbl(L_dollar);
        for (int i = 1; i < MAX_LOG_MESSAGES; i++) {
            L[i] = dbl(L[i - 1]);
        }
    }

    // Doubling operation in GF(2^128)
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
        assert i != 0;
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
                offset[j] ^= L[ntz(i + 1)][j];

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

        // Processing of remaining block
        // A_* is used to denote the last partial block (in RFC)
//        int rem_bytes = A.length & 0xF;
//        if (rem_bytes > 0){
//            // Offset_* = Offset_m XOR L_*
//            for (int i = 0; i < rem_bytes; i++) {
//                c_in[i] = (byte) (A[(m << 4) + i] ^ offset[i] ^ L_ast[i]);
//            }
//
//            // CipherInput = (A_* || 1 || zeros(127 - bitlength(A_*))) XOR Offset_*
//            // TODO: should this be with 0x80 or 1?
//            c_in[rem_bytes] = (byte) (0x80 ^ offset[rem_bytes] ^ L_ast[rem_bytes]);
//            for (int i = rem_bytes + 1; i < 16; i++) {
//                c_in[i] = (byte) (offset[i] ^ L_ast[i]);
//            }
//
//            // c_out = ENCIPHER(K, CipherInput)
//            cipher.processBlock(c_in, 0, c_out, 0);
//            for (int j = 0; j < 16; j++) {
//                sum[j] ^= c_out[j];
//            }
//        }

        // Cleaner version, following RFC pseudocode
        int rem_bytes = A.length & 0xF;
        if (rem_bytes > 0) {
            byte[] offset_star = new byte[16];
            for (int j = 0; j < 16; j++) {
                offset_star[j] = (byte) (offset[j] ^ L_ast[j]);
            }

            for (int i = 0; i < rem_bytes; i++) {
                c_in[i] = (byte) (A[(m << 4) + i] ^ offset_star[i]);
            }
            c_in[rem_bytes] = (byte) (0x80 ^ offset_star[rem_bytes]);
            System.arraycopy(offset_star, rem_bytes + 1, c_in, rem_bytes + 1, 16 - (rem_bytes + 1));

            // c_out = ENCIPHER(K, c_in)
            cipher.processBlock(c_in, 0, c_out, 0);

            // Sum = Sum_m XOR c_out
            for (int j = 0; j < 16; j++) {
                sum[j] ^= c_out[j];
            }
        }
    }

    public byte[] process(byte[] N, byte[] A, byte[] P) throws Exception {
        hash(A);
        int plen = P.length;
        if (decrypt) {
            plen -= 16;
        }
        byte[] C = new byte[plen + 16];
        byte[] nonce = new byte[16];
        nonce[15 - N.length] = 1;
        arraycopy(N, 0, nonce, 16 - N.length, N.length);
        int bottom = nonce[15] & 0x3f;
        nonce[15] &= (byte) 0xc0;
        cipher.processBlock(nonce, 0, offset, 0);
        long[] stretch = new long[3];
        for (int i = 0; i < 8; i++) {
            stretch[0] |= (long) offset[i]  << (56 - (i << 3));
            stretch[1] |= (long) offset[i + 8]  << (56 - (i << 3));
            stretch[2] |= (long) (offset[i] ^ offset[i + 1]) << (56 - (i << 3));
        }
        for (int i = 0; i < 2; i++) {
            stretch[i] = (stretch[i] << bottom) | (stretch[i + 1] >>> (64 - bottom));
        }
        for (int i = 0; i < 16; i++) {
            offset[i] = (byte) (stretch[i >> 3] >>> (56 - ((i & 7) << 3)));
        }
        final byte[] c_in = new byte[16];
        for (int i = 0; i < plen - 15; i += 16) {
            for (int j = 0; j < 16; j++) {
                offset[j] ^= L[ntz((i >>> 4) + 1) + 2][j];
                c_in[j] = (byte) (P[i + j] ^ offset[j]);
            }
            bid_cipher.processBlock(c_in, 0, C, i);
            for (int j = 0; j < 16; j++) {
                C[i + j] ^= offset[j];
                checksum[j] ^= P[i + j];
            }
        }
        int rem_bytes = plen & 0xf;
        if (rem_bytes > 0) {
            for (int j = 0; j < 16; j++) {
                offset[j] ^= L[0][j];
            }
            cipher.processBlock(offset, 0, c_in, 0);
            for (int j = 0; j < rem_bytes; j++) {
                C[(plen & 0xfffffff0) + j] = (byte) (c_in[j] ^ P[(plen & 0xfffffff0) + j]);
                checksum[j] ^= (byte) (offset[j] ^ L[1][j]);
                checksum[j] ^= P[(plen & 0xfffffff0) + j];
            }
            checksum[rem_bytes] ^= (byte) 1;
        }
        for (int i = rem_bytes; i < 16; i++) {
            checksum[i] ^= (byte) (offset[i] ^ L[1][i]);
        }
        cipher.processBlock(checksum, 0, C, plen);
        return C;
    }
    public boolean check_tag(byte[] o_tag, byte[] r_tag) {
        if (r_tag.length != o_tag.length) {
            return  false;
        }
        for (int i = 0; i < o_tag.length; i++) {
            if (o_tag[i] != r_tag[i]) {
                return false;
            }
        }
        return true;
    }
    public static void printhex(byte[] bb) {
        for (byte b : bb) {
            // pad with 0
            System.out.printf("%02X", b);
        }
        // new line for clarity
        System.out.println();
    }
    public static void main(String[] args) throws Exception {
        printhex(new OCB_AES(false,
                // Key
                java.util.HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F")
        ).process(
                // Nonce, can be 0 length
                java.util.HexFormat.of().parseHex("BBAA9988776655443322110F"),
                // Associated Data, any length
                java.util.HexFormat.of().parseHex(""),
                // Plaintext, any length
                java.util.HexFormat.of().parseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627")
        ));
        System.out.println("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479");
    }
}
