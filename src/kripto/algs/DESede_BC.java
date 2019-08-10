package kripto.algs;/*
 * Copyright (C) 2011 www.itcsolutions.eu
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1, or (at your
 * option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 *
 */

/**
 *
 * @author Catalin - www.itcsolutions.eu
 * @version june 2011
 *
 */
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.*;
import java.security.SecureRandom;

public class DESede_BC extends CryptoAlg {

    private PaddedBufferedBlockCipher encryptCipher;
    private PaddedBufferedBlockCipher decryptCipher;

    // Buffers used to transport the bytes from one stream to another
    private byte[] buf = new byte[8];       //input buffer - block size length
    private byte[] obuf = new byte[512];    //output buffer

    private byte[] key = null;              //the key

    public DESede_BC(){
        SecureRandom secureRandom = new SecureRandom();
        DESedeKeyGenerator keyGenerator = new DESedeKeyGenerator();
        //use a 192 bit key - if i:0 then key length is 192
        keyGenerator.init(new KeyGenerationParameters(secureRandom,0));
        key = keyGenerator.generateKey();
        // length of Base64 encoded key is 24
        System.out.println(key.length);
        InitCiphers();
    }

    private void InitCiphers(){
        encryptCipher = new PaddedBufferedBlockCipher(new DESedeEngine());
        encryptCipher.init(true, new KeyParameter(key));
        decryptCipher =  new PaddedBufferedBlockCipher(new DESedeEngine());
        decryptCipher.init(false, new KeyParameter(key));
    }

    public void ResetCiphers() {
        if(encryptCipher!=null)
            encryptCipher.reset();
        if(decryptCipher!=null)
            decryptCipher.reset();
    }

    public void encrypt(InputStream in, long length, OutputStream out)
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
            out.write(key);
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

    public void decrypt(InputStream in,long length, OutputStream out)
            throws ShortBufferException, IllegalBlockSizeException,  BadPaddingException,
            DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        try {
            // Bytes read from in will be decrypted
            // Read in the decrypted bytes from in InputStream and and
            //      write them in cleartext to out OutputStream

            // read key first
            byte [] readKey = new byte[24];
            in.read(readKey, 0, 24);
            key = readKey;

            int noBytesRead = 0;        //number of bytes read from input
            int noBytesProcessed = 0;   //number of bytes processed

            while ((noBytesRead = in.read(buf)) >= 0) {
                noBytesProcessed = decryptCipher.processBytes(buf, 0, noBytesRead, obuf, 0);
                out.write(obuf, 0, noBytesProcessed);
            }
            noBytesProcessed = decryptCipher.doFinal(obuf, 0);
            out.write(obuf, 0, noBytesProcessed);

            out.flush();
        }
        catch (java.io.IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        DESede_BC a = new DESede_BC();
        DESede_BC b = new DESede_BC();
        DESede_BC c = new DESede_BC();
        try {
            a.encrypt(new FileInputStream("Biljeske.txt"), 2, new FileOutputStream("sifra.txt"));
            a.decrypt(new FileInputStream("sifra.txt"), 2, new FileOutputStream("dekriptovano.txt"));
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException | InvalidCipherTextException | FileNotFoundException e) {
            e.printStackTrace();
        }
    }
}
