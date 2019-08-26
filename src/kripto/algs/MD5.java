package kripto.algs;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class MD5 {
    public static String generateHash(String input, byte[] salt) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("MD5");

        // add password to digest
        md.update(salt);

        // get the hash's bytes
        byte[] bytes = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static boolean validateHash(String input, String hash, byte[] salt) throws GeneralSecurityException {
        String tmp = MD5.generateHash(input, salt);
        return tmp.equals(hash);
    }

    public static byte[] getSalt() throws GeneralSecurityException {
        // using SecureRandom.generator
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
        // array for salt
        byte[] salt = new byte[16];
        // get random salt
        sr.nextBytes(salt);
        return salt;
    }
}