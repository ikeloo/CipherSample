package com.cipher.util;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
  
/** 
 * 将Java格式的RSA密钥转换为C#格式的密钥
 *  
 */
public class RSAJavaToCSharp {
    public static void main(String[] args) throws Exception {
        HashMap<String, Object> map = getKeys();
        RSAPublicKey publicKey = (RSAPublicKey) map.get("PUBLIC");
        RSAPrivateKey privateKey = (RSAPrivateKey) map.get("PRIVATE");
          
        String publicKeyString = getRSAPublicKeyAsNetFormat(publicKey.getEncoded());
        String privateKeyString = getRSAPrivateKeyAsNetFormat(privateKey.getEncoded());
          
        System.out.println("publicKeyString: \r\n" + publicKeyString);
        System.out.println("privateKeyString: \r\n" + privateKeyString);
    }
  
    /**获取密钥对 
     * @return 
     * @throws NoSuchAlgorithmException 
     */
    public static HashMap<String, Object> getKeys()
            throws NoSuchAlgorithmException {
        HashMap<String, Object> map = new HashMap<String, Object>();
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        map.put("PUBLIC", publicKey);
        map.put("PRIVATE", privateKey);
        return map;
    }
  
    /** 
     * 私钥转换成C#格式 
     * @param encodedPrivkey 
     * @return 
     */
    public static String getRSAPrivateKeyAsNetFormat(byte[] encodedPrivateKey) {
        try {
            StringBuffer buff = new StringBuffer(1024);
  
            PKCS8EncodedKeySpec pvkKeySpec = new PKCS8EncodedKeySpec(  
                    encodedPrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey pvkKey 
                = (RSAPrivateCrtKey) keyFactory.generatePrivate(pvkKeySpec);
  
            buff.append("<RSAKeyValue>");
            buff.append("<Modulus>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getModulus().toByteArray())))
                .append("</Modulus>");
            buff.append("<Exponent>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getPublicExponent().toByteArray())))
                .append("</Exponent>");
            buff.append("<P>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getPrimeP().toByteArray())))
                .append("</P>");
            buff.append("<Q>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getPrimeQ().toByteArray())))
                .append("</Q>");
            buff.append("<DP>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getPrimeExponentP().toByteArray())))
                .append("</DP>");
            buff.append("<DQ>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getPrimeExponentQ().toByteArray())))
                .append("</DQ>");
            buff.append("<InverseQ>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getCrtCoefficient().toByteArray())))
                .append("</InverseQ>");
            buff.append("<D>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pvkKey.getPrivateExponent().toByteArray())))
                .append("</D>");
            buff.append("</RSAKeyValue>");
  
            return buff.toString();
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }
  
    /** 
     * 公钥转成C#格式 
     * @param encodedPrivkey 
     * @return 
     */
    public static String getRSAPublicKeyAsNetFormat(byte[] encodedPublicKey) {
        try {
            StringBuffer buff = new StringBuffer(1024);
              
            //Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys   
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey pukKey = (RSAPublicKey) keyFactory  
                    .generatePublic(new X509EncodedKeySpec(encodedPublicKey));
  
            buff.append("<RSAKeyValue>");
            buff.append("<Modulus>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pukKey.getModulus().toByteArray())))
                .append("</Modulus>");
            buff.append("<Exponent>")
                .append(TranscodeUtil.byteArrayToBase64Str(
                        removeMSZero(pukKey.getPublicExponent().toByteArray())))
                .append("</Exponent>");
            buff.append("</RSAKeyValue>");
            return buff.toString();
        } catch (Exception e) {
            System.err.println(e);
            return null;
        }
    }

    /** 
     * 公钥转换成C#格式 
     * @param key 
     * @return 
     * @throws Exception 
     */
    public static String encodePublicKeyToXml(PublicKey key) throws Exception {
        if (!RSAPublicKey.class.isInstance(key)) {
            return null;
        }
        RSAPublicKey pubKey = (RSAPublicKey) key;
        StringBuilder sb = new StringBuilder();

        sb.append("<RSAKeyValue>");
        sb.append("<Modulus>")
          .append(TranscodeUtil.byteArrayToBase64Str(
                  removeMSZero(pubKey.getModulus().toByteArray())))
          .append("</Modulus>");
        sb.append("<Exponent>")
          .append(TranscodeUtil.byteArrayToBase64Str(
                  removeMSZero(pubKey.getPublicExponent().toByteArray())))
          .append("</Exponent>");
        sb.append("</RSAKeyValue>");
        return sb.toString();
    }

    /** 
     * @param data 
     * @return 
     */
    private static byte[] removeMSZero(byte[] data) {
        byte[] data1;
        int len = data.length;
        if (data[0] == 0) {
            data1 = new byte[data.length - 1];
            System.arraycopy(data, 1, data1, 0, len - 1);
        } else  
            data1 = data;
        return data1;
    }
}