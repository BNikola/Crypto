package kripto;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

public class UniversalAlgorithm {


    // region Members
    private PaddedBufferedBlockCipher encryptCipher;
    private PaddedBufferedBlockCipher decryptCipher;

    private static int KEY_LENGTH;
    private String algorithmName;

    // buffers to transfer bytes from one stream to another
    private byte[] inBuffer = new byte[16];
    private byte[] outBuffer = new byte[512];

    // key
    private byte[] key = null;
    // endregion

    // region Constructors
    public UniversalAlgorithm(String algorithmName) {
        InitProvider();
        this.algorithmName = algorithmName;
        switch (algorithmName) {
            case "AES":
                // generate key for aes
                KEY_LENGTH = 32;
                try {
                    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
                    keyGenerator.init(KEY_LENGTH);
                    key = keyGenerator.generateKey().getEncoded();
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    e.printStackTrace();
                }
                break;
            case "CAMELLIA": {
                // generate key for camellia
                KEY_LENGTH = 32;
                key = new byte[KEY_LENGTH];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(key);
                break;
            }
            case "DES3": {
                SecureRandom secureRandom = new SecureRandom();
                DESedeKeyGenerator keyGenerator = new DESedeKeyGenerator();
                // use 192 bit key - if i: 0 then key length is by default 192
                keyGenerator.init(new KeyGenerationParameters(secureRandom, 0));
                key = keyGenerator.generateKey();
                // length of the key is 24
                break;
            }
        }

        // init ciphers
        InitCiphers(algorithmName);
    }

    public UniversalAlgorithm(String algorithmName, byte[] keyBytes) {
        this.algorithmName = algorithmName;
        key = new byte[keyBytes.length];
        System.arraycopy(keyBytes, 0 , key, 0, keyBytes.length);
        InitCiphers(algorithmName);
    }

    // endregion

    // region Getters


    public String getAlgorithmName() {
        return algorithmName;
    }

    public static int getKeyLength() {
        return KEY_LENGTH;
    }

    public byte[] getKey() {
        return key;
    }
    // endregion

    // region Encrypt and Decrypt methods
    public void encrypt(InputStream in, OutputStream out) {
        try {
            // reading the clear text from in
            // writing encrypted text to out
            int noBytesRead = 0;            // number of bytes read from input
            int noBytesProcessed = 0;       // number of bytes processed to output
            while ((noBytesRead = in.read(inBuffer)) >= 0) {
                noBytesProcessed = encryptCipher.processBytes(inBuffer, 0, noBytesRead, outBuffer, 0);
                out.write(outBuffer, 0, noBytesProcessed);
            }
            noBytesProcessed = encryptCipher.doFinal(outBuffer, 0);

            // final write to out
            out.write(outBuffer, 0, noBytesProcessed);
            out.flush();
        } catch (IOException | InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public void decrypt(InputStream in, OutputStream out) {
        try {
            // reading encrypted text from in
            // writing decrypted text to out
            int noBytesRead = 0;            // number of bytes read from input
            int noBytesProcessed = 0;       // number of bytes processed to output
            while ((noBytesRead = in.read(inBuffer)) >= 0) {
                noBytesProcessed = decryptCipher.processBytes(inBuffer, 0, noBytesRead, outBuffer, 0);
                out.write(outBuffer, 0, noBytesProcessed);
            }
            noBytesProcessed = decryptCipher.doFinal(outBuffer, 0);

            // final write to out
            out.write(outBuffer, 0, noBytesProcessed);
            out.flush();
        } catch (IOException | InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }
    // endregion

    // region Private methods
    private void InitCiphers (String algorithmName) {
        switch (algorithmName) {
            case "AES":
                encryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
                encryptCipher.init(true, new KeyParameter(key));
                decryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
                decryptCipher.init(false, new KeyParameter(key));
                break;
            case "CAMELLIA":
                encryptCipher = new PaddedBufferedBlockCipher(new CamelliaEngine());
                encryptCipher.init(true, new KeyParameter(key));
                decryptCipher = new PaddedBufferedBlockCipher(new CamelliaEngine());
                decryptCipher.init(false, new KeyParameter(key));
                break;
            case "DES3":
                encryptCipher = new PaddedBufferedBlockCipher(new DESedeEngine());
                encryptCipher.init(true, new KeyParameter(key));
                decryptCipher = new PaddedBufferedBlockCipher(new DESedeEngine());
                decryptCipher.init(false, new KeyParameter(key));
                break;
        }
    }

    private void InitProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }
    // endregion
}
