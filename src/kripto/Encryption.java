package kripto;

import controllers.MainAppController;
import extraUtil.User;
import extraUtil.exceptions.*;
import kripto.algs.CertUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Encryption {


    // todo
    //  - add init() to functions

    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // when encrypting, generate key and store it into file
    public static void encryption(String pathToInput, String pathToOutput, String symmetricAlgorithm, String pathToUserCert, String hashingAlgorithm) throws CertificateException, IOException, CRLException, NoSuchAlgorithmException, CertificateOnCRLException, SignatureException, NoSuchProviderException, InvalidKeyException {
        UniversalAlgorithm algorithm = new UniversalAlgorithm(symmetricAlgorithm);
        X509Certificate userCert = CertUtil.loadCert(pathToUserCert);
        //CertUtil.checkValidityOfCertificate(userCert, MainAppController.rootCert, MainAppController.getPathToCrl());
        try (InputStream in = new FileInputStream(pathToInput); OutputStream out = new FileOutputStream(pathToOutput)) {
            // writing data for decryption and encrypting with certificate
            // separator
            byte[] separator = CertUtil.encryptAsymmetric(
                    "\n##############################\n".getBytes(StandardCharsets.UTF_8),
                    userCert);
            // userName
            out.write(
                    CertUtil.encryptAsymmetric(
                            MainAppController.user.getUsername().getBytes(StandardCharsets.UTF_8),
                            userCert));
            out.write(separator);
            // symmetric algorithm name
            out.write(
                    CertUtil.encryptAsymmetric(
                            algorithm.getAlgorithmName().getBytes(StandardCharsets.UTF_8),
                            userCert));
            out.write(separator);
            // symmetric algorithm key
            out.write(
                    CertUtil.encryptAsymmetric(
                            algorithm.getKey(),
                            userCert));
            out.write(separator);
            // create hash of the file
            ByteArrayInputStream bais = new ByteArrayInputStream(in.readAllBytes());
            String data = new String(bais.readAllBytes());
            bais.reset();       // reset hash so the symmetric encryption can be done
            Hashing hasher = new Hashing(hashingAlgorithm);
            byte[] hash = hasher.generateHash(data).getBytes(StandardCharsets.UTF_8);
            // hash algorithm
            out.write(
                    CertUtil.encryptAsymmetric(
                            hashingAlgorithm.getBytes(StandardCharsets.UTF_8),
                            userCert));
            // separator
            out.write(separator);
            // hash of the file
            out.write(
                    CertUtil.encryptAsymmetric(
                            hash,
                            userCert));
            out.write(separator);
            // name of the file
            Path p = Paths.get(pathToInput);
            String fileName = p.getFileName().toString();
            out.write(
                    CertUtil.encryptAsymmetric(
                            fileName.getBytes(StandardCharsets.UTF_8),
                            userCert));
            out.write(separator);

            algorithm.encrypt(bais, out);
            out.flush();
            bais.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    // when decrypting, remember to skip separator
    public static void decryption(String pathToInput, String pathToOutput, String sender) throws CertificateOnCRLException, WrongSenderException, HashMismatchException, CertificateException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        try (InputStream in = new FileInputStream(pathToInput)) {
            // reader for header
            byte[] reader = new byte[256];  // 256 is the size of RSA encryption
            // read username
            in.read(reader);
            String userName = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            if (!userName.equals(sender)) {
                throw new WrongSenderException();
            }
            // check validity of certificate CertUtil.checkValidityOfCertificate(new User());
            X509Certificate senderCert = CertUtil.loadCertFromUsername(userName);
            CertUtil.checkValidityOfCertificate(senderCert, MainAppController.rootCert, MainAppController.getPathToCrl());
            // read separator
            in.read(reader);
            System.out.println(new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey())));
            // read symmetric algorithm name
            in.read(reader);
            String algorithmName = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            System.out.println(algorithmName);
            // read separator
            in.read(reader);
            System.out.println(new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey())));
            // read symmetric algorithm key
            in.read(reader);
            byte[] algorithmKey = CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey());
            System.out.println(algorithmKey.length + "||||");
            // read separator
            in.read(reader);
            // read hashing algorithm name
            in.read(reader);
            String hashingAlgorithmName = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            // read separator
            in.read(reader);
            System.out.println(new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey())).length() + "|||");
            // read hash of file
            in.read(reader);
            String hash = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            System.out.println(hash);
            // read separator
            in.read(reader);
            System.out.println(new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey())));
            // read filename
            in.read(reader);
            String fileName = new String(CertUtil.decryptAsymmetric(reader, MainAppController.user.getPrivateKey()));
            System.out.println(fileName + "|");
            MainAppController.decryptedFileName = fileName;
            OutputStream out = new FileOutputStream(pathToOutput + File.separator + fileName);
            in.read(reader);
            // create algorithm and call decrypt
            UniversalAlgorithm algorithm = new UniversalAlgorithm(algorithmName, algorithmKey);
            System.out.println(algorithm.getKey().length);
            algorithm.decrypt(in, out);
            out.close();
            Hashing hasher = new Hashing(hashingAlgorithmName);
            boolean hashValidator = hasher.validateHash(new String(Files.readAllBytes(Paths.get(pathToOutput + File.separator + fileName))), hash);
            if (!hashValidator) {
                throw new HashMismatchException();
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (CRLException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        init();
//        FileInputStream in;
//        FileOutputStream out;
//        try {
//
//
////            in = new FileInputStream("testEnkripcije.txt");
////            out = new FileOutputStream("sifra.txt");
////            Encryption.enkripcija(in, out, "AES");
//
//
//
//            Encryption.dekripcija(new FileInputStream("sifra.txt"), new FileOutputStream("dekriptovano.txt"), "AES");
////            Encryption.dekripcija(new FileInputStream("umirem.txt"), new FileOutputStream("dekriptovano.txt"), "CAMELLIA");
////            Encryption.dekripcija(new FileInputStream("sifra.txt"), new FileOutputStream("dekriptovano.txt"), "DES3");
////
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        }
        try {
            MainAppController.user = new User("Korisnik2", "/home/korisnik/Faks/Projektni/CRL/certs/korisnik2.crt", "sigurnost2");
            Encryption.encryption("/home/korisnik/Faks/Projektni/src/extraUtil/Test.java", "sifra.txt", "AES", "/home/korisnik/Faks/Projektni/CRL/certs/korisnik2.crt", "MD5");
//            Encryption.decryption("sifra.txt", "dekriptovaneDatoteke", "Korisnik2");
        } catch (PasswordException | WrongCredentials | CertificateOnCRLException | CertPathException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}







































