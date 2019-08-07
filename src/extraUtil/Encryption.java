package extraUtil;

import kripto.algs.CryptoAlg;
import kripto.algs.MyAES;
import kripto.algs.MyCamellia;
import kripto.algs.MyDES;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class Encryption {

    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

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


    private static void dekripcija(FileInputStream fileInputStream, FileOutputStream fileOutputStream, String alg) {

        if (alg.equals("AES")) {
            try {
                byte[] key = new byte[MyAES.getKeyLength()];
                fileInputStream.read(key);
                MyAES algorithm = new MyAES(key);
                fileInputStream.read(key);
                algorithm.decrypt(fileInputStream, fileOutputStream);
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (alg.equals("CAMELLIA")) {
            try {
                byte[] key = new byte[MyCamellia.getKeyLength()];
                fileInputStream.read(key);
                MyCamellia algorithm = new MyCamellia(key);
                fileInputStream.read(key);
                algorithm.decrypt(fileInputStream, fileOutputStream);
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (alg.equals("DES3")) {
            try {
                byte[] key = new byte[MyDES.getKeyLength()];
                fileInputStream.read(key);
                MyDES algorithm = new MyDES(key);
                fileInputStream.read(key);
                algorithm.decrypt(fileInputStream, fileOutputStream);
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void enkripcija(FileInputStream in, FileOutputStream out, String alg) {
        if (alg.equals("AES")) {
            try {
                MyAES algorithm = new MyAES();
                out.write(algorithm.getKey());
                out.write("\n##############################\n".getBytes(StandardCharsets.UTF_8));
                algorithm.encrypt(in, out);
                out.flush();
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (ShortBufferException e) {
                e.printStackTrace();
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            }
        } else if (alg.equals("CAMELLIA")) {
            try {
                MyCamellia algorithm = new MyCamellia();
                out.write(algorithm.getKey());
                out.write("\n##############################\n".getBytes(StandardCharsets.UTF_8));
                algorithm.encrypt(in, out);
                out.flush();
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (ShortBufferException e) {
                e.printStackTrace();
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            }
        } else if (alg.equals("DES3")) {
            try {
                MyDES algorithm = new MyDES();
                out.write(algorithm.getKey());
                out.write("\n######################\n".getBytes(StandardCharsets.UTF_8));
                algorithm.encrypt(in, out);
                out.flush();
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            }
        }


    }

    public static void main(String[] args) {
        init();
        FileInputStream in;
        FileOutputStream out;
        try {
//            in = new FileInputStream("testEnkripcije.txt");
//            out = new FileOutputStream("sifra.txt");
//            Encryption.enkripcija(in, out, "AES");
//            Encryption.dekripcija(new FileInputStream("umirem.txt"), new FileOutputStream("dekriptovano.txt"), "CAMELLIA");
            Encryption.dekripcija(new FileInputStream("sifra.txt"), new FileOutputStream("dekriptovano.txt"), "AES");
//            Encryption.dekripcija(new FileInputStream("umirem.txt"), new FileOutputStream("dekriptovano.txt"), "DES3");
//
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}
