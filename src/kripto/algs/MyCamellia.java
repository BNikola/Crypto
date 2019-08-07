package kripto.algs;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.security.SecureRandom;

public class MyCamellia {

    private PaddedBufferedBlockCipher encryptCipher;
    private PaddedBufferedBlockCipher decryptCipher;

    private static final int KEY_LENGTH = 32;

    // buffers to transfer bytes from one stream to another
    private byte[] buf = new byte[16];
    private byte[] obuf = new byte[512];

    private byte[] key = new byte[KEY_LENGTH];

    // region Constructors
    public MyCamellia() {
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        InitCiphers();

    }

    public MyCamellia(byte[] keyBytes) {
        key = new byte[keyBytes.length];
        System.arraycopy(keyBytes, 0 , key, 0, keyBytes.length);
        InitCiphers();
    }
    // endregion

    // region Getters and setters

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
        encryptCipher = new PaddedBufferedBlockCipher(new CamelliaEngine());
        encryptCipher.init(true, new KeyParameter(key));
        decryptCipher = new PaddedBufferedBlockCipher(new CamelliaEngine());
        decryptCipher.init(false, new KeyParameter(key));
    }

    public void encrypt(InputStream in, OutputStream out)
            throws ShortBufferException,
            IllegalBlockSizeException,
            BadPaddingException,
            DataLengthException,
            IllegalStateException,
            InvalidCipherTextException
    {
        try {
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
