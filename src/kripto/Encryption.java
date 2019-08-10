package kripto;

import com.sun.tools.javac.Main;
import controllers.MainAppController;
import extraUtil.Test;
import extraUtil.User;
import kripto.algs.CertUtil;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Encryption {

    // todo
    //  - create class for RSA
    //  - add hash of the document
    //  - add init() to functions
    //  - replace file input/output streams with file paths
    //  - add certificate validation when it is being used

    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
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
                PemReader reader = new PemReader(new InputStreamReader(new FileInputStream("/home/korisnik/Faks/Projektni/CRL/private/korisnik2.key")));
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
            } catch (IOException | BadPaddingException | IllegalBlockSizeException | ShortBufferException | InvalidCipherTextException e) {
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
            } catch (IOException | BadPaddingException | IllegalBlockSizeException | ShortBufferException | InvalidCipherTextException e) {
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
            } catch (IOException | InvalidCipherTextException e) {
                e.printStackTrace();
            }
        }
    }

    // when encrypting, generate key and store it into file
    public static void encryption(String pathToInput, String pathToOutput, String symmetricAlgorithm) {
        UniversalAlgorithm algorithm = new UniversalAlgorithm(symmetricAlgorithm);
        try (InputStream in = new FileInputStream(pathToInput); OutputStream out = new FileOutputStream(pathToOutput)) {
            // writing data for decryption and encrypting with certificate
            // separator
            byte[] separator = CertUtil.encryptAsymmetric(
                    "\n##############################\n".getBytes(StandardCharsets.UTF_8),
                    MainAppController.user.getCertificate());
            // userName
            out.write(
                    CertUtil.encryptAsymmetric(
                            MainAppController.user.getUsername().getBytes(StandardCharsets.UTF_8),
                            MainAppController.user.getCertificate()));
            out.write(separator);
            // symmetric algorithm name
            out.write(
                    CertUtil.encryptAsymmetric(
                            algorithm.getAlgorithmName().getBytes(StandardCharsets.UTF_8),
                            MainAppController.user.getCertificate()));
            out.write(separator);
            // symmetric algorithm key
            out.write(
                    CertUtil.encryptAsymmetric(
                            algorithm.getKey(),
                            MainAppController.user.getCertificate()));
            out.write(separator);
            // create hash of the file
//            ByteArrayInputStream bais = new ByteArrayInputStream(in.readAllBytes());
//            String data = new String(bais.readAllBytes());
//            bais.reset();       // reset hash so the symmetric encryption can be done
            String data = new String(Files.readAllBytes(Paths.get(pathToInput)));       // read without bais
            byte[] hash = Hashing.generateHashSHA512(data).getBytes(StandardCharsets.UTF_8);
            // hash of the file
            out.write(
                    CertUtil.encryptAsymmetric(
                            hash,
                            MainAppController.user.getCertificate()));
            out.write(separator);

//            algorithm.encrypt(bais, out);
            algorithm.encrypt(in, out);
            out.flush();
//            bais.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    // when decrypting, remember to skip separator
    public static void decryption(String pathToInput, String pathToOutput) {
        try (InputStream in = new FileInputStream(pathToInput); OutputStream out = new FileOutputStream(pathToOutput)) {
            // reader for header
            byte[] reader = new byte[256];  // 256 is the size of RSA encryption
            // read username
            in.read(reader);
            String userName = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            // check validity of certificate CertUtil.checkValidityOfCertificate(new User());
            // read separator
            in.read(reader);
            // read symmetric algorithm name
            String algorithmName = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            // read separator
            in.read(reader);
            // read symmetric algorithm key
            byte[] algorithmKey = CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey());
            // read separator
            in.read(reader);
            // read hash of file
            String hash = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            // read separator
            in.read(reader);
            // create algorithm and call decrypt
            UniversalAlgorithm algorithm = new UniversalAlgorithm(algorithmName, algorithmKey);
            algorithm.decrypt(in, out);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
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
            Encryption.dekripcija(new FileInputStream("/home/korisnik/Faks/Projektni/kriptovaneDatoteke/test1.txt"), new FileOutputStream("dekriptovano.txt"), "AES");
//            Encryption.dekripcija(new FileInputStream("sifra.txt"), new FileOutputStream("dekriptovano.txt"), "DES3");
//
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}







































