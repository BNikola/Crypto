package kripto.algs;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class MyDES {

    private PaddedBufferedBlockCipher encryptCipher;
    private PaddedBufferedBlockCipher decryptCipher;

    private static final int KEY_LENGTH = 24;


    // buffers to transfer bytes from one stream to another
    private byte[] buf = new byte[16];
    private byte[] obuf = new byte[512];
    private byte[] key = null;

    // region Constructors
    public MyDES() {
        SecureRandom secureRandom = new SecureRandom();
        DESedeKeyGenerator keyGenerator = new DESedeKeyGenerator();
        //use a 192 bit key - if i:0 then key length is 192
        keyGenerator.init(new KeyGenerationParameters(secureRandom,0));
        key = keyGenerator.generateKey();
        // length of Base64 encoded key is 24
        System.out.println(key.length);
        InitCiphers();
    }

    public MyDES(byte[] keyBytes) {
        key = new byte[keyBytes.length];
        System.arraycopy(keyBytes, 0 , key, 0, keyBytes.length);
        InitCiphers();
    }

    // endregion

    // region Getters and Setters

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public static int getKeyLength() {
        return KEY_LENGTH;
    }

    // endregion

    private void InitCiphers() {
        encryptCipher = new PaddedBufferedBlockCipher(new DESedeEngine());
        encryptCipher.init(true, new KeyParameter(key));
        decryptCipher = new PaddedBufferedBlockCipher(new DESedeEngine());
        decryptCipher.init(false, new KeyParameter(key));
    }

//    public byte[] encrypt(byte[] in) {
//
//    }

    public void encrypt(InputStream in, OutputStream out)
            throws DataLengthException,
            IllegalStateException,
            InvalidCipherTextException
    {
        try {
            // Bytes written to out will be encrypted
            // Read in the cleartext bytes from in InputStream and
            //      write them encrypted to out OutputStream
            int noBytesRead = 0;        //number of bytes read from input
            int noBytesProcessed = 0;   //number of bytes processed
            while ((noBytesRead = in.read(buf)) >= 0) {
                noBytesProcessed =
                        encryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
                out.write(obuf, 0, noBytesProcessed);
            }
            noBytesProcessed =
                    encryptCipher.doFinal(obuf, 0);


            out.write(obuf, 0, noBytesProcessed);

            out.flush();
        }
        catch (java.io.IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public void decrypt(InputStream in, OutputStream out) throws InvalidCipherTextException {
        try {
            int noBytesRead = 0;
            int noBytesProcessed = 0;

            while ((noBytesRead = in.read(buf)) >= 0) {
                noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
                out.write(obuf, 0, noBytesProcessed);
            }
            noBytesProcessed = decryptCipher.doFinal(obuf, 0);
            out.write(obuf, 0, noBytesProcessed);

            out.flush();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
