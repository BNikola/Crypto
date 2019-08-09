package extraUtil;

import exceptions.CertPathException;
import exceptions.PasswordException;
import exceptions.WrongCredentials;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class User {

    // region Members
    private String username;
    private String pathToCert;
    private String pathToPrivateKey;

    private X509Certificate certificate;
    private PrivateKey privateKey;
    // endregion

    // region Constructors

    public User(String username, String pathToCert, String passwordHash) throws WrongCredentials, PasswordException, CertPathException {
        this.username = username;
        this.pathToCert = pathToCert;

        // path to private key is in the file users.txt
        try {
            FileInputStream fis = new FileInputStream("users.txt");
            // read content of users.txt
            byte[] data = fis.readAllBytes();
            String users = new String(data);

            if (!users.contains(username + "#")) {
                // if there is no username throw exception
                throw new WrongCredentials();
            } else {
                // find index of line with the username
                // users must have '\n' at the end of file
                int startIndex = users.indexOf(username + "#");
                int endIndex = users.indexOf('\n', startIndex);
                String[] line = users.substring(startIndex, endIndex).split("#");

                // validate password hash
                if (!Hashing.validateHashSHA256(passwordHash, line[1])) {
                    throw new PasswordException();
                } else if (!pathToCert.equals(line[2])) {
                    throw new CertPathException("Wrong path to certificate!");
                }

                this.pathToPrivateKey = line[3];
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

     /*
     * users.txt format
     * username # password hash # path to certificate # path to private key
     */
    // endregion

    // region Getters and setters

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPathToCert() {
        return pathToCert;
    }

    public void setPathToCert(String pathToCert) {
        this.pathToCert = pathToCert;
    }

    public String getPathToPrivateKey() {
        return pathToPrivateKey;
    }

    public void setPathToPrivateKey(String pathToPrivateKey) {
        this.pathToPrivateKey = pathToPrivateKey;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    // endregion

    public X509Certificate loadCert() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(pathToCert));   // read cert in X509 format
        return cert;
    }

    public PrivateKey loadKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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

    @Override
    public String toString() {
        return username;
    }
}
