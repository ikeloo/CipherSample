package com.cipher.test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import com.cipher.util.CipherUtil;
import com.cipher.util.RSAJavaToCSharp;
import com.cipher.util.TranscodeUtil;

public class CipherTest {
	//tt
    String rsaPrivateKey;
    String rsaPublicKey;
    String aesKeyClient;
    String aesKeyServer;
    
    public void initRSA() {
        Map<String, Object> keyMap = CipherUtil.initRSAKey(1024);
        
        rsaPrivateKey = CipherUtil.getRSAPrivateKeyBase64(keyMap);
        rsaPublicKey = CipherUtil.getRSAPublicKeyBase64(keyMap);
        
        // 公钥详细内容
        RSAPublicKey keyRsaPublicKey = CipherUtil.getRSAPublicKey(keyMap);
        String csharpRSAPubKey = RSAJavaToCSharp.getRSAPublicKeyAsNetFormat(keyRsaPublicKey.getEncoded());
        
        // 私钥详细内容
        RSAPrivateKey keyRsaPrivateKey = CipherUtil.getRSAPrivateKey(keyMap);
        String csharpRSAPriKey = RSAJavaToCSharp.getRSAPrivateKeyAsNetFormat(keyRsaPrivateKey.getEncoded());
        
//        rsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlbW1BIB3pku2sL4Zm/XDNHz6kirY/dTYUWlJ1wW94LW3N3R2MWF1Mekzr+oVyTIV0lmjyI/5eW0d/qKhXH7Cxlhd8X0V/hRSFW8HIBG8nHvvJAOupXmJcHD8zisQ3Kax/Ja6BJHmPCKt4h2UIpZi9xEU5V4u45D2lV5wd19DytjdTiuvy8yTseJ04kmfUKdF2zVKit2TGmg4+QIlOPQkgh8wRrNAiVNFvcpq/556vsYdqSaR49YVhcfdXhrNRpm7VZsidaTu/bDreWwU2zuaDZtS0uLe8qOOQ4GhXVkTBslwMMvFliCohSBOMNwsBUiqk3gmOnFxJ7qy/t59n/HVhQIDAQAB";
//        rsaPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCVtbUEgHemS7awvhmb9cM0fPqSKtj91NhRaUnXBb3gtbc3dHYxYXUx6TOv6hXJMhXSWaPIj/l5bR3+oqFcfsLGWF3xfRX+FFIVbwcgEbyce+8kA66leYlwcPzOKxDcprH8lroEkeY8Iq3iHZQilmL3ERTlXi7jkPaVXnB3X0PK2N1OK6/LzJOx4nTiSZ9Qp0XbNUqK3ZMaaDj5AiU49CSCHzBGs0CJU0W9ymr/nnq+xh2pJpHj1hWFx91eGs1GmbtVmyJ1pO79sOt5bBTbO5oNm1LS4t7yo45DgaFdWRMGyXAwy8WWIKiFIE4w3CwFSKqTeCY6cXEnurL+3n2f8dWFAgMBAAECggEAXE5lBhmPrGESi3cqoxas/Tfx5x20HQ2XMtsQRBuuL1bbWL3eAiRs9hErZVOXiy3udnv+mDLtRwkYbWAozbb6sQDbK4JMhRRSaBTE9+j3uiRQFoyOqkh9jW6c8SFsjB/brjnhB+BNbNaVD83dAFZpPpyxnZqsnnNLFl3cSj3atr5+e/ycSWznkKTJ/V3ER0Myyqb1OMHA3xZyte33El061L+dsQMARnotQiuZSu+NaCNzJq2OvjTjjN5SAnB+cpuNSqhIV1nUFBRa9vWxmo3v2BJXfReo4Q8D8PthVe3932IaevIgoF3gFwpCUjroaPfDCP1viMKu4liBWAWEaokKIQKBgQDIKLM6ypM2zUp4k1bOoRyFxGd/B+qQ3NXjc6VWlJEsspIZMfWtjB5BQ3zyu4XP2hes3mJQjz3UukN39vy1C4MAGWTNc48Bad+xBnixAJzf1AGuEaDk0KjdYRKIo211Qgu9AO47m+1xc1Xa28rg/mq+n5uordqK+UT+50caaNvWWwKBgQC/efCF/vyJdXgJ4LblvOz2B4mGlZtrDDXtcOHegPuKrXoEk+ZdqUKtoVK4CNewkl3iaPGiAoQR8+ZSpTA7ymhh5HHQoFriy5Dd7nYMHr2t+Ooug9XVFDGzeCfsRNjJ7hk4wWXajC07S7Tmz3wQxHiUuOn4AsSrDZ78ncGuBeOJnwKBgQCr1CzRCrjIcgI9cpcx+aNnvozuw5f91mcTxOKqag4a5g1/7aCv5LrQYiRwqMUeA2cRszOJXv7AkUp8QR7+OSyzuBkOOucIWqB680hHA3SovfLXQTDzXaGpsrzbahj8cb9r+NGLgLedDlsk8EzBTAfNL23Mp7sWVRmDDn6+0EfxQwKBgQCaqduf0MSaH9mzWOFDlyRs4s+yd1wPztAsmBbKTLNiZBgAZJsaoqLqbznKz9GxnbjaLlynuZKGkdVEgowAb9F66TUKCM0BDt9YdMrDpX0fbsVyhykNMX+n8PGGhmH6UinrT0R/kOTkVZWtLoGPZbPkpazPmSTU6m62rJMKh1UxDwKBgHvN3U+yhN89JGXS+Lh8cAvXH9ToJQv2F8KU5mbwFsD+QNc1pN+mvGGn5Yp4H0V6XsFsOVR5MbAjObrGkrEstNa9LiP6QJlUGufD0a9xGjfAKhIMALdSY8ZZTpHE+GTDukfAY6HtDCvaZm8IulflJIcjMtfUENAE0hJJZTlfUkAY";
        System.out.println("公钥Java: " + rsaPublicKey);
        System.out.println("私钥Java: " + rsaPrivateKey);
        
        System.out.println("公钥dotNet: " + csharpRSAPubKey);
        System.out.println("私钥dotNet: " + csharpRSAPriKey);
    }
    
    public void rsaTest() {
        String str = "1234567890123456789012345678901234567890";
        
        // 公钥加密 -> 私钥解密
        byte[] encBytePub = CipherUtil.RSAEncryptByPublicKey(str.getBytes(), rsaPublicKey);
        byte[] decBytePri = CipherUtil.RSADecryptByPrivateKey(encBytePub, rsaPrivateKey);
        System.out.println("公钥加密 encBytePub: " + new String(TranscodeUtil.byteArrayToHexStr(encBytePub)));
        System.out.println("私钥解密 decBytePri: " + new String(decBytePri));
        
        // 私钥加密 -> 公钥解密
        byte[] encBytePri = CipherUtil.RSAEncryptByPrivateKey(str.getBytes(), rsaPrivateKey);
        byte[] decBytePub = CipherUtil.RSADecryptByPublicKey(encBytePri, rsaPublicKey);
        System.out.println("私钥加密 encBytePri: " + new String(TranscodeUtil.byteArrayToHexStr(encBytePri)));
        System.out.println("公钥解密 decBytePub: " + new String(decBytePub));
        
        // 签名
        String originalStr = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        String signStr = CipherUtil.RSASign(originalStr.getBytes(), rsaPrivateKey);
        System.out.println("签名后的字符串 signStr: " + signStr);
        boolean bVeri = CipherUtil.RSAVerify(originalStr.getBytes(), rsaPublicKey, signStr);
        System.out.println("bVeri: " + bVeri);
    }
    
    /**
     * @param args
     */
    public static void main(String[] args) {
        CipherTest test = new CipherTest();
        test.initRSA();
        test.rsaTest();
//        String loginToServerStr = test.loginToServer("abcd1234567890","user001");
//        
//        boolean bLogin = test.serverProcessLogin(loginToServerStr);
//        
//        System.out.println("Login result: " + bLogin);
    }
    
    /**
     * STEP 1
     * C端实现B端获取对称密钥到S端 
     * @param userId
     * @param sn
     * @param aesKey
     * @return
     */
    public String loginToServer(String userId, String sn) {
        String strRet = null;
        // 生成AES密钥
        aesKeyClient = CipherUtil.generateAESKey(128, "abcdefgh");
        String targetStr = sn + ";" + userId + ";" + aesKeyClient;
        // 公钥加密【串号】【用户名】【AES密钥】
        byte[] encBytePub = CipherUtil.RSAEncryptByPublicKey(targetStr.getBytes(), rsaPublicKey);
        
        strRet = TranscodeUtil.byteArrayToBase64Str(encBytePub);
        return strRet;
    }
    
    /**
     * S端实现处理来自B端的通信开始请求
     * @param encValue
     * @return
     */
    public boolean serverProcessLogin(String encValue) {
        boolean bRet = false;
        byte[] data = TranscodeUtil.base64StrToByteArray(encValue);
        byte[] decBytePri = CipherUtil.RSADecryptByPrivateKey(data, rsaPrivateKey);
        String strDecPri = new String(decBytePri);
        
        String[] valueParts = strDecPri.split(";");
        String sn = null;
        String userId = null;
        if (valueParts.length == 3) {
            sn = valueParts[0];
            userId = valueParts[1];
            aesKeyServer = valueParts[2];
            bRet = true;
        }
        
        return bRet;
    }
    

}
