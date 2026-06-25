// Fixture 10: encrypt(). Reviewer should flag CWE-327.
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class TokenCipher {

    public byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec spec = new SecretKeySpec(key, "DES");
        c.init(Cipher.ENCRYPT_MODE, spec);
        return c.doFinal(plaintext);
    }
}
