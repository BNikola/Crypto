package kripto.algs;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class MyAES {

    private PaddedBufferedBlockCipher encryptCipher;
    private PaddedBufferedBlockCipher decryptCipher;

    private static final int KEY_LENGTH = 32;


    // buffers to transfer bytes from one stream to another
    byte[] buf = new byte[16];
    byte[] obuf = new byte[512];
    private byte[] key = null;

    // region Constructors
    public MyAES() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            key = keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        InitCiphers();

    }

    public MyAES(byte[] keyBytes) {
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
        encryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
        encryptCipher.init(true, new KeyParameter(key));
        decryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
        decryptCipher.init(false, new KeyParameter(key));
    }

//    public byte[] encrypt(byte[] in) {
//
//    }

    public void encrypt(InputStream in, OutputStream out)
            throws ShortBufferException,
            IllegalBlockSizeException,
            BadPaddingException,
            DataLengthException,
            IllegalStateException,
            InvalidCipherTextException
    {
        try {
            // Bytes written to out will be encrypted
            // Read in the cleartext bytes from in InputStream and
            //      write them encrypted to out OutputStream
            //out.write(key);
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
//            byte [] readKey = new byte[32];
//            in.read(readKey, 0, 32);
//            key = readKey;

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

    public static void main(String[] args) {
        MyAES a = new MyAES();
        MyAES b;

        try {
            FileInputStream fis;
//            FileOutputStream fos = new FileOutputStream("teeeeest.txt");
//            fos.write(a.key);
//            fos.write("\n##############################\n".getBytes(StandardCharsets.UTF_8));
//            fos.flush();
//            fos.close();

            fis = new FileInputStream("teeeeest.txt");
            // read key and separator
            byte[] bytes = new byte[32];
            fis.read(bytes);
            b = new MyAES(bytes);
            fis.close();


//            a.encrypt(new FileInputStream("testEnkripcije.txt"), new FileOutputStream("umirem.txt"));
            b.decrypt(new FileInputStream("umirem.txt"), new FileOutputStream("dekriptovano2.txt"));


        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}


























