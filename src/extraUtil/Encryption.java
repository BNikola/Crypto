package extraUtil;

import kripto.algs.CryptoAlg;
import kripto.algs.MyAES;
import kripto.algs.MyCamellia;
import kripto.algs.MyDES;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Encryption {

    // todo
    //  - create class for RSA and certs
    //  - create methods for reading private key, reading x509
    //  - add hash of the document
    //  - add init() to functions
    //  - replace file input/output streams with file paths
    //  - add certificate validation when it is being used

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
//                byte[] key = new byte[MyAES.getKeyLength()];
//                fileInputStream.read(key);
//                MyAES algorithm = new MyAES(key);
//                fileInputStream.read(key);
                byte[] read = new byte[256];

                // load private key
                PemReader reader = new PemReader(new InputStreamReader(new FileInputStream("private2048.key")));
                PemObject pemObject = reader.readPemObject();

                // private key
                KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
                PrivateKey pk = kf.generatePrivate(privateKeySpec);
                reader.close();

                // reading alg name
                fileInputStream.read(read);
                String algName = new String(Test.decrypt(read, pk));
                System.out.println(algName);
                // reading alg key
                fileInputStream.read(read);
                MyAES algorithm = new MyAES(Test.decrypt(read, pk));
                fileInputStream.read(read);
                fileInputStream.read(read);
                String hash = new String(Test.decrypt(read, pk));
                System.out.println(hash);
                fileInputStream.read(read);

                algorithm.decrypt(fileInputStream, fileOutputStream);
            } catch (InvalidCipherTextException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            } catch (Exception e) {
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
//                pisanje u fajl bez enkripcije sa rsa
//                out.write(algorithm.getKey());
//                out.write("\n##############################\n".getBytes(StandardCharsets.UTF_8));

//                pisanje u fajl sa rsa enkripcijom
                X509Certificate cert = Test.loadCert("user1.crt");
                out.write(Test.encrypt("AES".getBytes(StandardCharsets.UTF_8), cert.getPublicKey()));
                out.write(Test.encrypt(algorithm.getKey(), cert.getPublicKey()));
                out.write(Test.encrypt("\n##############################\n".getBytes(StandardCharsets.UTF_8), cert.getPublicKey()));

                // kreiranje hash-a
                ByteArrayInputStream bais = new ByteArrayInputStream(in.readAllBytes());
                byte[] data = bais.readAllBytes();
                bais.reset();
                String d = new String(data);
                byte[] hash = Hashing.generateHashSHA256(d).getBytes(StandardCharsets.UTF_8);
                System.out.println(new String(hash));
                out.write(Test.encrypt(hash, cert.getPublicKey()));
                out.write(Test.encrypt("\n##############################\n".getBytes(StandardCharsets.UTF_8), cert.getPublicKey()));


                algorithm.encrypt(bais, out);
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
            } catch (Exception e) {
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
//            Encryption.enkripcija(in, out, "DES3");


//            Encryption.dekripcija(new FileInputStream("umirem.txt"), new FileOutputStream("dekriptovano.txt"), "CAMELLIA");
//            Encryption.dekripcija(new FileInputStream("sifra.txt"), new FileOutputStream("dekriptovano.txt"), "AES");
            Encryption.dekripcija(new FileInputStream("sifra.txt"), new FileOutputStream("dekriptovano.txt"), "DES3");
//
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}
