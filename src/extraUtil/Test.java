package extraUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

public class Test {
    public static X509Certificate loadCert(String path) throws Exception {
        CertificateFactory cf;
        X509Certificate cert;
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate)cf.generateCertificate(new FileInputStream(path));  //read certificate in x.509 format from path
        return cert;
    }

    public static byte[] encrypt(byte[] text, PublicKey publicKey) throws Exception {
        byte[] cipherText = null;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipherText = cipher.doFinal(text);

        return cipherText;
    }

    public static byte[] decrypt(byte[] text, PrivateKey privateKey) throws Exception {
        byte[] cipherText = null;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        cipherText = cipher.doFinal(text);

        return cipherText;
    }

    public static void main(String[] args) {
//        try {
//            X509Certificate cert = Test.loadCert("user1.crt");
//            System.out.println(cert.getPublicKey());
//            // duzina je 256 fiksno
//            System.out.println(Test.encrypt("\n######################################################################################################################################################\n".getBytes(StandardCharsets.UTF_8), cert.getPublicKey()).length);
//            System.out.println(Test.encrypt("DES3".getBytes(StandardCharsets.UTF_8), cert.getPublicKey()).length);
//            System.out.println(Test.encrypt("AES".getBytes(StandardCharsets.UTF_8), cert.getPublicKey()).length);
//            System.out.println(Test.encrypt("CAMELLIA".getBytes(StandardCharsets.UTF_8), cert.getPublicKey()).length);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        Security.addProvider(new BouncyCastleProvider());
        try {
//            PemReader reader = new PemReader(new InputStreamReader(new FileInputStream("private2048.key")));
            PemReader reader = new PemReader(new InputStreamReader(new FileInputStream("CRL/private/korisnik1-enc.pem")));
            PemObject pemObject = reader.readPemObject();

            System.out.println(pemObject.getContent());
            System.out.println(pemObject.getType());

            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            PrivateKey pk = kf.generatePrivate(privKeySpec);
            System.out.println(pk.getFormat());
            reader.close();

            X509Certificate cert = Test.loadCert("CRL/certs/korisnik1.crt");
            // duzina je 256 fiksno
            byte [] test = Test.encrypt("AES".getBytes(StandardCharsets.UTF_8), cert.getPublicKey());
            System.out.println(test.length);
            System.out.println(new String(Test.decrypt(test, pk)));
            System.out.println(cert.getNotAfter());
            System.out.println(Arrays.toString(cert.getKeyUsage()));
            // check validity of user cert
//            try {
//                cert.checkValidity(new Date());
//            } catch (Exception e) {
//                e.printStackTrace();
//            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

//        try {
//            // load user cert
////            X509Certificate userCert = Test.loadCert("CRL/certs/korisnik5.crt");
//            X509Certificate userCert = Test.loadCert("user1.crt");
//            // load root cert
//            X509Certificate rootCert = Test.loadCert("CRL/rootca.crt");
//
//            // verify user cert with root cert
//            userCert.verify(rootCert.getPublicKey());
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }
}



//KeyUsage ::= BIT STRING {
//        digitalSignature        (0),
//        nonRepudiation          (1),
//        keyEncipherment         (2),
//        dataEncipherment        (3),
//        keyAgreement            (4),
//        keyCertSign             (5),
//        cRLSign                 (6),
//        encipherOnly            (7),
//        decipherOnly            (8) }


























