package extraUtil;

import org.bouncycastle.jcajce.provider.symmetric.DES;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class Encryption {

    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // region Encryption with 3DES
//    private static byte[] encodeDES3(byte[] input, Certificate cert) throws GeneralSecurityException {
//        init();
//        DES.ECB alg = new DES.ECB();
//        DES.KeyGenerator kg = new DES.KeyGenerator();
//        Cipher encrypter = Cipher.getInstance("DESede/ECB/PKCS7Padding", "BC");
//
//        encrypter.init(Cipher.ENCRYPT_MODE, build);



//    }

    private PrivateKey loadKey(String path) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // key from user certificate
        PrivateKey key;
        File f = new File(path);
        DataInputStream dis = new DataInputStream(new FileInputStream(f)); // file input stream for reading bytes, f contains key
        byte [] privateUserKey = new byte[(int)f.length()];     // byte array for reading the key
        dis.read(privateUserKey); // reading data (bytes)
        dis.close();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // rsa is used for private key
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateUserKey); // PKCS8 contains pair of keys, PKCS12 contains cert and keys
        key = keyFactory.generatePrivate(privateSpec);
        return key;
    }

    public static X509Certificate loadCert(String path) throws Exception {
        CertificateFactory cf;
        X509Certificate cert;
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate)cf.generateCertificate(new FileInputStream(path));  //read certificate in x.509 format from path
        return cert;
    }

    public static void main(String[] args) {
        init();
        try {
            Certificate cert = loadCert("user1.crt");
            System.out.println(cert.getPublicKey());
//            byte[] test = encodeDES3("sigurnost".getBytes(StandardCharsets.UTF_8), cert);
//            System.out.println(Base64.encode(test));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
