package com.cipher.test;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import com.cipher.util.CipherUtil;
import com.cipher.util.RSAJavaToCSharp;
import com.cipher.util.TranscodeUtil;

public class CipherTest {

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
        
        rsaPrivateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANRoiRzyaHkwoRbj" +
			"Nysc0wRG87xTy/4YD6EW1BgEJZsTwe8KRDMt0omyKQaFBW/CgtpT5kQjVR4iKc6c" +
			"9yLfysxRFYeGxnLcbSTH9fHYg7kD95B0XuYcBe2kb/sDDplaUS4Rmudmet6DxoOv" +
			"4PyUbhlac80y0cidAHsBz4RBU29RAgMBAAECgYEAlxnKOFJlaZjjb6GxVDUME+XZ" +
			"a6Z83kQFkkXoGTGSAvCaLE80VugI9rVLo/yq8mb/qQq4Ks6rtWT+MqHM2P00iLpp" +
			"oH2TPBYhfisWN9gSLZD5/dQeeeahe3uTOgkmOuqlytuCq1DQ3pdXs8WBQVcE6VkB" +
			"C4N/jAJj9cnaiUPdqAECQQDuKrjKwDg29NpMbCHYh5QlBl+n3Cv5h/6rLWySs5kH" +
			"crOesgIy/GMIoB5eTSa8+ibEgnqWjwt/MakRMWKS696BAkEA5FAQUaQ52/A0JELH" +
			"uSkoDgqoy4VE9E9Nc/iOHkuSKYRr9MsE7nWHlnYG4yVk2DFdu9hx+l3bPxK0leic" +
			"re7I0QJBAM09C5nNI6RYRHZvCIur6kItx+jDlzGlvBSPRGz3T/xXH+q1w6dkT4Nz" +
			"WDgzjBp2B0p4lmOASYwGo4cpY6TwlgECQHWDUCL1aGJv7CaNyMbhDCDOE7tNSQSG" +
			"nNMIJ/4n339HDVnd9RfXnoYvEbRwVst//ULmUSQQkvyP4CsYoyxTL0ECQQDjdmWo" +
			"w2J5a3LwuF8YzcM6NdTphxjd1U35BUI9/V9R9olaMlU5XiBJXf/B/L55bEpM4meR" +
			"0LSCI7KhnSV4PWjD";

        rsaPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUaIkc8mh5MKEW4zcrHNMERvO8" +
        		"U8v+GA+hFtQYBCWbE8HvCkQzLdKJsikGhQVvwoLaU+ZEI1UeIinOnPci38rMURWH" +
        		"hsZy3G0kx/Xx2IO5A/eQdF7mHAXtpG/7Aw6ZWlEuEZrnZnreg8aDr+D8lG4ZWnPN" +
        		"MtHInQB7Ac+EQVNvUQIDAQAB";

        try {
			rsaPublicKey = this.testFileRead("d:\\rsa_key\\rsa_public_key.pem");
			rsaPrivateKey = this.testFileRead("d:\\rsa_key\\rsa_private_key_pem.pem");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        System.out.println("公钥Java: " + rsaPublicKey);
        System.out.println("私钥Java: " + rsaPrivateKey);
        
        System.out.println("公钥dotNet: " + csharpRSAPubKey);
        System.out.println("私钥dotNet: " + csharpRSAPriKey);
        
        
        String strAESKey = CipherUtil.generateAESKey(128, "abcd1234");
        System.out.println("AES密钥: " + strAESKey);
        
    }
    
    public void rsaTest() throws UnsupportedEncodingException {
        String str = "1234567890123456789012345678901234567890";
        
        // 公钥加密 -> 私钥解密
        byte[] encBytePub = CipherUtil.RSAEncryptByPublicKey(str.getBytes(), rsaPublicKey);
        byte[] decBytePri = CipherUtil.RSADecryptByPrivateKey(encBytePub, rsaPrivateKey);
        System.out.println("公钥加密 encBytePub: " + new String(TranscodeUtil.byteArrayToHexStr(encBytePub)));
        System.out.println("公钥加密 encBytePub(base64): " + new String(TranscodeUtil.byteArrayToBase64Str(encBytePub)));
        System.out.println("私钥解密 decBytePri: " + new String(decBytePri));
        
        // 私钥加密 -> 公钥解密
        byte[] encBytePri = CipherUtil.RSAEncryptByPrivateKey(str.getBytes(), rsaPrivateKey);
        byte[] decBytePub = CipherUtil.RSADecryptByPublicKey(encBytePri, rsaPublicKey);
        System.out.println("私钥加密 encBytePri: " + new String(TranscodeUtil.byteArrayToHexStr(encBytePri)));
        System.out.println("私钥加密 encBytePri(base64): " + new String(TranscodeUtil.byteArrayToBase64Str(encBytePri)));
        System.out.println("公钥解密 decBytePub: " + new String(decBytePub));
        
        // 签名
        String originalStr = "1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名1234567890签名签名";
        System.out.println("签名的原始内容: " + originalStr);
        String signStr = "";
		signStr = CipherUtil.RSASign(originalStr.getBytes("UTF-8"), rsaPrivateKey);
        System.out.println("签名后的字符串 signStr: " + signStr);
        boolean bVeri = CipherUtil.RSAVerify(originalStr.getBytes("UTF-8"), rsaPublicKey, signStr);
        System.out.println("bVeri: " + bVeri);
        
        String orginalText = "Everything is going to be 200 OK";
        
        byte[] aaaEnc = CipherUtil.RSAEncryptByPublicKey(orginalText.getBytes(), rsaPublicKey);
        String aaaBase64 = TranscodeUtil.byteArrayToBase64Str(aaaEnc);
        System.out.println("公钥加密后：" + aaaBase64);
        
        byte[] data111 = TranscodeUtil.base64StrToByteArray("gZL6eCbwoYppZx+cZ+rOtJExfDRoVj/KQsd5imo7NZkGEj2NP7XQKYb0eUQABzKC7IQ5Zt4UZnMEal9tumWn6hliyXMyx9njlzWWW7LRIYQ1G1JwQUQ6A6NU0BmJrSXnFUkGJU2CvsUXbInmrf78tTKq7VjWptVf9SYXZr6Zrog=");
        byte[] aaaa = CipherUtil.RSADecryptByPrivateKey(data111, rsaPrivateKey);
        try {
			String abdd = new String(aaaa, "UTF-8");
			System.out.println(abdd);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
        System.out.println("===================================================================");
        // 公钥加密 -> 私钥解密
        byte[] encBytePub2 = CipherUtil.RSAEncryptByPublicKey(str.getBytes(), rsaPublicKey);
        byte[] decBytePri2 = CipherUtil.RSADecryptByPrivateKey(encBytePub2, rsaPrivateKey);
        System.out.println("公钥加密 encBytePub2: " + new String(TranscodeUtil.byteArrayToHexStr(encBytePub2)));
        System.out.println("公钥加密 encBytePub2(base64): " + new String(TranscodeUtil.byteArrayToBase64Str(encBytePub2)));
        System.out.println("私钥解密 decBytePri2: " + new String(decBytePri2));
        
        
        System.out.println("###################################################");
        // 签名
        
//        String vSign = "LHVj+AnSdzrbinRsarT4AV3vJkTDYfB1QrP10J/s9KUcf06iNua7oszf/NcnRWFlXoSAibqfvmSqIrDuYB4ZIbPFxxg4NYNBlXm/Tic3ZBLxU9LpN5YWA9u57sVkas5h7t+uoSYoUQgHOcODscjzP4XzPlB5OuADJ+hHJ3sKYyU=";
        String vSign = "YnjkW9B7LEQe3KScT6hc+7Trlz/5xUb7hbDtPYgrY2NR2qK0iu8/UJuwiqjGjMqO3ST1pCDGxbvAPpc0mX0HBKAN+p9Fpi+hD6rq0xk6lX7XSsQPYhXbm9RHV+wmaumzI1WmsvzLUwVFt8BDeBQmHINfTjrFE8NCD2fj7AMakU0=";
//        String yuanwen = "测试数据";
        String yuanwen = "1234567890签名签名";
        String yuanwenMD5 = CipherUtil.MD5Encode(yuanwen, "UTF-8");
        
        System.out.println("yuanwenMD5: " + yuanwenMD5);
        
        boolean bVeri2 = CipherUtil.RSAVerify(yuanwenMD5.getBytes(), rsaPublicKey, vSign);
        System.out.println("bVeri2: " + bVeri2);
    }
    
    /**
     * @param args
     * @throws UnsupportedEncodingException 
     */
    public static void main(String[] args) throws UnsupportedEncodingException {
        CipherTest test = new CipherTest();
        test.initRSA();
        test.rsaTest();
//        String loginToServerStr = test.loginToServer("abcd1234567890","user001");
//        
//        boolean bLogin = test.serverProcessLogin(loginToServerStr);
//        
//        System.out.println("Login result: " + bLogin);
        
        try {
			test.testFileRead("d:\\rsa_key\\rsa_public_key.pem");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
    }
    
	public String testFileRead(String filePathName) throws IOException {
		BufferedReader br = new BufferedReader(new FileReader(filePathName));
		String s = br.readLine();
		String str = "";
		s = br.readLine();
		while (s.charAt(0) != '-') {
			str += s;
			s = br.readLine();
			
		}
		if (br != null) {
			br.close();
		}
		return str;
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
