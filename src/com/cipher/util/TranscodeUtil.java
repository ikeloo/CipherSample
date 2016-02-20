package com.cipher.util;

  
/** 
 * 该类处理字符串的转码，可以处理字符串到二进制字符、16进制字符、unicode字符、base64字符之间的转换 
 * 
 */  
public class TranscodeUtil {  
  
    /** 
     * 将字节数组通过base64转码 
     * @param byteArray 字节数组 
     * @return 返回转码后的字符串 
     */  
    public static String byteArrayToBase64Str(byte byteArray[]) {  
        return new String(encode(byteArray));  
    }  
  
    /** 
     * 将base64码转换成字节数组 
     * @param base64Str base64码 
     * @return 返回转换后的字节数组 
     */  
    public static byte[] base64StrToByteArray(String base64Str) {  
        char[] dataArr = new char[base64Str.length()];  
        base64Str.getChars(0, base64Str.length(), dataArr, 0);  
        return decode(dataArr);  
    }  
  
    /** 
     * 将一个字节数组转换成base64的字符数组 
     * @param data 字节数组 
     * @return base64字符数组 
     */  
    private static char[] encode(byte[] data) {  
        char[] out = new char[((data.length + 2) / 3) * 4];  
        for (int i = 0, index = 0; i < data.length; i += 3, index += 4) {  
            boolean quad = false;  
            boolean trip = false;  
            int val = (0xFF & (int) data[i]);  
            val <<= 8;  
            if ((i + 1) < data.length) {  
                val |= (0xFF & (int) data[i + 1]);  
                trip = true;  
            }  
            val <<= 8;  
            if ((i + 2) < data.length) {  
                val |= (0xFF & (int) data[i + 2]);  
                quad = true;  
            }  
            out[index + 3] = alphabet[(quad ? (val & 0x3F) : 64)];  
            val >>= 6;  
            out[index + 2] = alphabet[(trip ? (val & 0x3F) : 64)];  
            val >>= 6;  
            out[index + 1] = alphabet[val & 0x3F];  
            val >>= 6;  
            out[index + 0] = alphabet[val & 0x3F];  
        }  
        return out;  
    }  
  
    /** 
     * 将一个base64字符数组解码成一个字节数组 
     * @param data base64字符数组 
     * @return 返回解码以后的字节数组 
     */  
    private static byte[] decode(char[] data) {  
        int len = ((data.length + 3) / 4) * 3;  
        if (data.length > 0 && data[data.length - 1] == '=') --len;  
        if (data.length > 1 && data[data.length - 2] == '=') --len;  
        byte[] out = new byte[len];  
        int shift = 0;  
        int accum = 0;  
        int index = 0;  
        for (int ix = 0; ix < data.length; ix++) {  
            int value = codes[data[ix] & 0xFF];  
            if (value >= 0) {  
                accum <<= 6;  
                shift += 6;  
                accum |= value;  
                if (shift >= 8) {  
                    shift -= 8;  
                    out[index++] = (byte) ((accum >> shift) & 0xff);  
                }  
            }  
        }  
        if (index != out.length)  
            throw new Error("miscalculated data length!");  
        return out;  
    }  
  
    /** 
     * base64字符集 0..63 
     */  
    static private char[] alphabet =  
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toCharArray();  
  
    /** 
     * 初始化base64字符集表 
     */  
    static private byte[] codes = new byte[256];  
  
    static {  
        for (int i = 0; i < 256; i++) codes[i] = -1;  
        for (int i = 'A'; i <= 'Z'; i++) codes[i] = (byte) (i - 'A');  
        for (int i = 'a'; i <= 'z'; i++) codes[i] = (byte) (26 + i - 'a');  
        for (int i = '0'; i <= '9'; i++) codes[i] = (byte) (52 + i - '0');  
        codes['+'] = 62;  
        codes['/'] = 63;  
    }  

    /** 
     * 将字节数组转换成16进制字符串 
     * @param byteArray 要转码的字节数组 
     * @return 返回转码后的16进制字符串 
     */  
    public static String byteArrayToHexStr(byte byteArray[]) {  
        StringBuffer buffer = new StringBuffer(byteArray.length * 2);  
        int i;  
        for (i = 0; i < byteArray.length; i++) {  
            if (((int) byteArray[i] & 0xff) < 0x10)//小于十前面补零  
                buffer.append("0");  
            buffer.append(Long.toString((int) byteArray[i] & 0xff, 16));  
        }  
        return buffer.toString();  
    }  
  
    /** 
     * 将16进制字符串转换成字节数组 
     * @param hexStr 要转换的16进制字符串 
     * @return 返回转码后的字节数组 
     */  
    public static byte[] hexStrToByteArray(String hexStr) {  
        if (hexStr.length() < 1)  
            return null;  
        byte[] encrypted = new byte[hexStr.length() / 2];  
        for (int i = 0; i < hexStr.length() / 2; i++) {  
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);//取高位字节  
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);//取低位字节  
            encrypted[i] = (byte) (high * 16 + low);  
        }  
        return encrypted;  
    }  

}  