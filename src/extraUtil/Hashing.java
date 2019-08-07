package extraUtil;

import org.bouncycastle.jcajce.provider.digest.BCMessageDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Hashing {

    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // region Generating hash: MD5, SHA256, SHA512

    public static String generateHashMD5(String input) throws GeneralSecurityException {
        init();
        BCMessageDigest md = (BCMessageDigest) BCMessageDigest.getInstance("MD5", "BC");
        final byte [] hashBytes= md.digest(input.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.encode(hashBytes));
    }

    public static String generateHashSHA256(String input) throws GeneralSecurityException {
        init();
        BCMessageDigest md = (BCMessageDigest) BCMessageDigest.getInstance("SHA256", "BC");
        final byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.encode(hashBytes));
    }

    public static String generateHashSHA512(String input) throws GeneralSecurityException {
        init();
        BCMessageDigest md = (BCMessageDigest) BCMessageDigest.getInstance("SHA512", "BC");
        final byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.encode(hashBytes));
    }

    // endregion

    // region Validating hash: MD5, SHA256, SHA512

    public static boolean validateHashMD5(String input, String hash) throws GeneralSecurityException {
        init();
        BCMessageDigest md = (BCMessageDigest) BCMessageDigest.getInstance("MD5", "BC");
        final byte[] hashbytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
        String hashedInput = new String(Base64.encode(hashbytes));

        if (hashedInput.equals(hash)) {
            return true;
        }else {
            return false;
        }
    }

    public static boolean validateHashSHA256(String input, String hash) throws GeneralSecurityException {
        init();
        BCMessageDigest md = (BCMessageDigest) BCMessageDigest.getInstance("SHA256", "BC");
        final byte[] hashbytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
        String hashedInput = new String(Base64.encode(hashbytes));

        if (hashedInput.equals(hash)) {
            return true;
        }else {
            return false;
        }
    }

    public static boolean validateHashSHA512(String input, String hash) throws GeneralSecurityException {
        init();
        BCMessageDigest md = (BCMessageDigest) BCMessageDigest.getInstance("SHA512", "BC");
        final byte[] hashbytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
        String hashedInput = new String(Base64.encode(hashbytes));

        if (hashedInput.equals(hash)) {
            return true;
        }else {
            return false;
        }
    }

    // endregion

    public static String whichHashingAlg(String hash) {
        int length = hash.length();
        if (length == 24) {
            return "MD5";
        } else if (length == 44) {
            return "SHA256";
        } else if (length == 88) {
            return "SHA512";
        }
        return "No such algorithm";
    }
}
