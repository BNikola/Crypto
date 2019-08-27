package kripto.algs;

import controllers.Cryptography;
import extraUtil.exceptions.CertificateOnCRLException;
import kripto.Hashing;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Level;

public class CertUtil {

    private static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate loadCert(String pathToCert) throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(pathToCert));   // read cert in X509 format
        return cert;
    }

    public static X509Certificate loadCertFromUsername(String username) {
        File users = new File("/home/korisnik/Faks/Projektni/users.txt");
        String pathToCert = "";
        X509Certificate cert = null;
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(users))) {
            String line = "";
            while ((line = bufferedReader.readLine()) != null) {
                String [] lineArray = line.split("#");
                if (lineArray[0].equals(username)) {
                    pathToCert = lineArray[2];
                }
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(new FileInputStream(pathToCert));   // read cert in X509 format
            return cert;
        } catch (IOException | CertificateException e) {
            Cryptography.LOGGER.log(Level.SEVERE, e.toString(), e);
        }
        return cert;
    }

    public static X509CRL loadCRL(String pathToCRL) throws CertificateException, CRLException, IOException {
        InputStream inputStream = new FileInputStream(pathToCRL);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(inputStream);
            inputStream.close();
            return crl;

    }
    // keys must be in DER format

    public static PrivateKey loadKey(String pathToPrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        init();

        // key for user cert
        PrivateKey key;
        File f = new File(pathToPrivateKey);
        DataInputStream dis = new DataInputStream(new FileInputStream(f));
        byte[] privateUserKey = new byte[(int) f.length()];         // creating byte array for reading key
        dis.read(privateUserKey);           // reading the key
        dis.close();

        // creating the key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  // rsa is used for private keys
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateUserKey); //PKCS8 contains pair of keys pub and priv
        key = keyFactory.generatePrivate(privateSpec);

        return key;
    }

    public static void checkValidityOfCertificate(X509Certificate certificate, X509Certificate rootCert, String pathToCRL)
            throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException,
                    InvalidKeyException, SignatureException, CRLException, IOException, CertificateOnCRLException {
        init();
        certificate.verify(rootCert.getPublicKey());
        certificate.checkValidity();
        X509CRL crl = loadCRL(pathToCRL);
        if (crl.getRevokedCertificate(certificate) != null) {
            throw new CertificateOnCRLException();
        }
    }

    public static byte[] generateSignature(PrivateKey privateKey, byte[] input, String hashingAlgorithmName) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        init();
        Signature signature = Signature.getInstance(hashingAlgorithmName + "withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    public static boolean verifySignature(X509Certificate certificate, byte[] input, byte[] encSignature, String hashingAlgorithmName) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        init();
        Signature signature = Signature.getInstance(hashingAlgorithmName + "withRSA", "BC");
        signature.initVerify(certificate);
        signature.update(input);
        return signature.verify(encSignature);
    }

    public static byte[] encryptAsymmetric(byte[] input, X509Certificate certificate) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] cipherText = null;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
        cipherText = cipher.doFinal(input);

        return cipherText;
    }

    public static byte[] decryptAsymmetric(byte[] input, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] decryptedText = null;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedText = cipher.doFinal(input);

        return decryptedText;
    }
}































