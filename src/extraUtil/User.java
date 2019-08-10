package extraUtil;

import extraUtil.exceptions.CertPathException;
import extraUtil.exceptions.PasswordException;
import extraUtil.exceptions.WrongCredentials;
import kripto.Hashing;
import kripto.algs.CertUtil;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

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

                this.certificate = CertUtil.loadCert(pathToCert);
                System.out.println(pathToPrivateKey);
                this.privateKey = CertUtil.loadKey(pathToPrivateKey);
            }
        } catch (IOException | GeneralSecurityException e) {
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



    @Override
    public String toString() {
        return username;
    }
}
