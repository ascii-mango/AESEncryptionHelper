package com.techmali.aes;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class AESHelper
{
    private static final char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    private static SecretKeySpec getSecretKey(final String myKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return new SecretKeySpec(HexFromString(myKey), "AES");
    }

    private static byte[] HexFromString(String s) {
        int i = s.length();
        byte abyte0[] = new byte[(i + 1) / 2];
        int j = 0;
        int k = 0;
        if (i % 2 == 1)
            abyte0[k++] = (byte) HexFromDigit(s.charAt(j++));
        while (j < i)
            abyte0[k++] = (byte) (HexFromDigit(s.charAt(j++)) << 4 | HexFromDigit(s.charAt(j++)));
        return abyte0;
    }

    private static int HexFromDigit(char c) {
        if (c >= '0' && c <= '9')
            return c - 48;
        if (c >= 'A' && c <= 'F')
            return (c - 65) + 10;
        if (c >= 'a' && c <= 'f')
            return (c - 97) + 10;
        else
            throw new IllegalArgumentException("invalid hex digit '" + c + "'");
    }

    public static String encrypt(final String strToEncrypt, final String secretKey)
    {
        try
        {
            final SecretKeySpec key = getSecretKey(secretKey);
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            final byte encstr[] = cipher.doFinal(strToEncrypt.getBytes());
            return HexToString(encstr);
        }
        catch (Exception e)
        {
            throw new RuntimeException("Error while encrypting message:" + e.getMessage());
        }
    }

    private static String HexToString(final byte bytes[]) {
        return HexToString(bytes, 0, bytes.length);
    }

    private static String HexToString(final byte bytes[], final int i, final int j) {
        char ac[] = new char[j * 2];
        int k = 0;
        for (int l = i; l < i + j; l++) {
            byte byte0 = bytes[l];
            ac[k++] = hexDigits[byte0 >>> 4 & 0xf];
            ac[k++] = hexDigits[byte0 & 0xf];
        }

        return new String(ac);
    }


    public static String decrypt(final String strToDecrypt, final String secretKey)
    {
        try {
            final SecretKeySpec key = getSecretKey(secretKey);
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            if (strToDecrypt != null && !strToDecrypt.equals("")) {
                byte encStr[] = cipher.doFinal(HexFromString(strToDecrypt));
                return new String(encStr).trim();
            } else {
                return "";
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException | BadPaddingException e) {
            throw new RuntimeException("Error while decrypting message:" + e.getMessage());
        }
    }
}
