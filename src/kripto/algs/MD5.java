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
        // todo - delete everything that is not useful
//        System.out.println("Validation");
//        System.out.println("aaa: " + tmp.equals(hash));
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

    public static void main(String[] args) {
        String password = "";
        try {
//            for(int i=1; i<6; i++) {
//                password = "sigurnost" + i;
//                String generatePass = "";
//                byte [] salt = MD5.getSalt();
//                generatePass = MD5.generateHashSHA256(password, salt);
//                System.out.println(password + "#" + Base64.getEncoder().encodeToString(salt) + "#" + generatePass);
//            }
            BufferedReader br = new BufferedReader(new FileReader("users.txt"));
            String sadrzaj = br.readLine();
            String sadrzaj2 = br.readLine();
            String [] s = sadrzaj.split("#");
            byte [] b = Base64.getDecoder().decode(s[1]);
            System.out.println("salt: " + b);
            System.out.println(s[0]);
            System.out.println(s[1]);
            System.out.println(s[2]);
            System.out.println(MD5.validateHash(s[0], s[2], b));
            br.close();



        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }


    }
}