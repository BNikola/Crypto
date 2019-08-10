package kripto.algs;

import extraUtil.exceptions.CertificateOnCRLException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertUtil {

    public static X509Certificate loadCert(String pathToCert) throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(pathToCert));   // read cert in X509 format
        return cert;
    }

    public static X509CRL loadCRL(String pathToCRL) throws CertificateException, CRLException, IOException {
        InputStream inputStream = new FileInputStream(pathToCRL);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(inputStream);
            inputStream.close();
            return crl;

    }

    public static PrivateKey loadKey(String pathToPrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());

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

        certificate.verify(rootCert.getPublicKey());
        X509CRL crl = loadCRL(pathToCRL);
        if (crl.getRevokedCertificate(certificate) != null) {
            throw new CertificateOnCRLException();
        }
    }
}
