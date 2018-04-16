package com.utils;

/**
 * Created by DONGYA RSA加密解密签名验签
 */

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * 1024位的证书，加密时最大支持117个字节，解密时为128；
 * 2048位的证书，加密时最大支持245个字节，解密时为256。
 * 加密时支持的最大字节数：证书位数/8 -11（比如：2048位的证书，支持的最大加密字节数：2048/8 - 11 = 245）
 */
public class RSAUtil {

    public static final String KEY_ALGORITHM = "RSA";//加密算法

    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";//签名算法

    private static final String PUBLIC_KEY = "RSAPublicKey";//公钥

    private static final String PRIVATE_KEY = "RSAPrivateKey";//私钥

    //RSA最大加密明文大小
    private static final int MAX_ENCRYPT_BLOCK = 117;

    //RSA最大解密密文大小
    private static final int MAX_DECRYPT_BLOCK = 128;


    private static RSAPrivateKey privateKey;
    private static Cipher deCipher;
    private static Map<String, RSAPublicKey> publicKeyMap = new HashMap<>();
    private static Map<String, Cipher> enCipherMap = new HashMap<>();
    private static Map<String, String> signKeyMap = new HashMap<>();


    /**
     * RSA签名--并用base64加密
     *
     * @param privateKeyStr:私钥
     * @param signKey:签名key
     * @param content:待签名字符串
     * @return 签名结果
     * @throws Exception
     */
    public static String sign(String privateKeyStr, String signKey, String content) {
        try {
            Signature signature = Signature.getInstance("SHA1WithRSA");
            signature.initSign(loadPrivateKey(privateKeyStr));
            signature.update(Base64.decodeBase64(content + signKey));
            byte[] signResult = signature.sign();
            return Base64.encodeBase64String(signResult);
        } catch (NoSuchAlgorithmException e) {
        } catch (Exception e) {
        }
        return null;
    }

    /**
     * 初始化私钥、解密系统
     */
    private static void initPrivateKeyAndDeCipher() {
        try {
            String aa = null;
            privateKey = loadPrivateKey(aa);
            deCipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            deCipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (Exception e) {
        }
    }


    /**
     * 初始化公钥、加密系统
     */
    private static void initPublicKeyAndEnCipher(JSONObject js) {
        try {
            String partnerId = js.getString("partnerId");
            String key = js.getString("publicKey");
            String signKey = js.getString("signKey");

            RSAPublicKey publicKey = loadPublicKey(key);
            Cipher enCipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            enCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            publicKeyMap.put(partnerId, publicKey);
            enCipherMap.put(partnerId, enCipher);
            signKeyMap.put(partnerId, signKey);
        } catch (Exception e) {
        }
    }


    /**
     * 从文件中输入流中加载公钥
     *
     * @param in 公钥输入流
     * @throws Exception 加载公钥时产生的异常
     */
    public RSAPublicKey loadPublicKeyByStream(InputStream in) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null) {
                if (readLine.charAt(0) == '-') {
                    continue;
                } else {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            return loadPublicKey(sb.toString());
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }


    /**
     * 从文件中加载私钥
     *
     * @return 是否成功
     * @throws Exception
     */
    public RSAPrivateKey loadPrivateKeyByStream(InputStream in) throws Exception {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(in));
            String readLine = null;
            StringBuilder sb = new StringBuilder();
            while ((readLine = br.readLine()) != null) {
                if (readLine.charAt(0) == '-') {
                    continue;
                } else {
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            return loadPrivateKey(sb.toString());
        } catch (IOException e) {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥输入流为空");
        }
    }

    public static RSAPrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (IOException e) {
            throw new Exception("私钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }


    /**
     * 公钥加密数据
     *
     * @param partnerId
     * @param content
     * @return
     * @throws Exception
     */
    public static String encryptByPartnerId(String partnerId, String content) throws Exception {
        RSAPublicKey publicKey = publicKeyMap.get(partnerId);
        Cipher enCipher = enCipherMap.get(partnerId);
        byte[] plainTextData = content.getBytes();
        if (publicKey == null) {
            throw new Exception("加密公钥为空, 请设置");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            int inputLen = plainTextData.length;
            int offSet = 0;
            byte[] cache;
            int i = 0;
            Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = enCipher.doFinal(plainTextData, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = enCipher.doFinal(plainTextData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] buffer = out.toByteArray();
            return Base64.encodeBase64String(buffer);
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        } finally {
            out.close();
        }

    }


    /**
     * 私钥解密数据
     *
     * @param content
     * @return
     * @throws Exception
     */
    public static String decryptByDefaultKey(String content) throws Exception {
        byte[] buffer = Base64.decodeBase64(content);
        if (privateKey == null) {
            throw new Exception("解密私钥为空, 请设置");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            int inputLen = buffer.length;
            int offSet = 0;
            //对数据分段解密
            for (int i = 0; inputLen - offSet > 0; offSet = i * MAX_DECRYPT_BLOCK) {
                byte[] cache;
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = deCipher.doFinal(buffer, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = deCipher.doFinal(buffer, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
            }
            byte[] plainText = out.toByteArray();
            return new String(plainText);
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        } finally {
            out.close();
        }
    }

    /**
     * 加密过程
     *
     * @param publicKey 公钥
     * @param content   明文字符串
     * @return
     * @throws Exception 加密过程中的异常信息
     */
    public static byte[] encrypt(RSAPublicKey publicKey, String content) throws Exception {
        byte[] plainTextData = content.getBytes();
        if (publicKey == null) {
            throw new Exception("加密公钥为空, 请设置");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            int inputLen = plainTextData.length;
            int offSet = 0;
            byte[] cache;
            int i = 0;
            Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > 117) {
                    cache = cipher.doFinal(plainTextData, offSet, 117);
                } else {
                    cache = cipher.doFinal(plainTextData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * 117;
            }
            return out.toByteArray();
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        } finally {
            out.close();
        }
    }

    /**
     * 解密过程
     *
     * @param privateKey 私钥
     * @param cipherData 密文数据
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData) throws Exception {
        if (privateKey == null) {
            throw new Exception("解密私钥为空, 请设置");
        }
        Cipher cipher = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            int inputLen = cipherData.length;
            int offSet = 0;
            byte[] cache;
            int i = 0;
            //对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(cipherData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(cipherData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            return out.toByteArray();
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            throw new Exception("解密私钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        } finally {
            out.close();
        }
    }


    /**
     * RSA验签--并用base64加密
     *
     * @param publicKeyStr 公钥
     * @param signKey      签名key
     * @param content      签名原文
     * @param sign         待验证签名
     * @return 验签结果
     * @throws Exception
     */
    public static boolean verify(String publicKeyStr, String signKey, String content, String sign) throws Exception {
        try {
            Signature signature = Signature.getInstance("SHA1WithRSA");
            signature.initVerify(loadPublicKey(publicKeyStr));
            signature.update(Base64.decodeBase64(content + signKey));
            return signature.verify(Base64.decodeBase64(sign));
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }


    public static RSAPublicKey loadPublicKey(String publicKeyStr) throws Exception {
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] buffer = base64Decoder.decodeBuffer(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (IOException e) {
            throw new Exception("公钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }


    public static void initKey() throws Exception {

        KeyPairGenerator keyPairGen = KeyPairGenerator
                .getInstance(KEY_ALGORITHM);
        /*
         *  从代码中可以看出密钥的初始化长度为1024位，密钥的长度越长，安全性就越好，但是加密解密所用的时间就会越多。而一次能加密的密文长度也与密钥的长度成正比。
         *  一次能加密的密文长度为：密钥的长度/8-11。所以1024bit长度的密钥一次可以加密的密文为1024/8-11=117bit。
         *  所以非对称加密一般都用于加密对称加密算法的密钥，而不是直接加密内容。对于小文件可以使用RSA加密，但加密过程仍可能会使用分段加密。
         * */
        keyPairGen.initialize(1024);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        System.out.println("publicKey--->:  " + encryptBASE64(publicKey.getEncoded()));

        System.out.println("privateKey--->:  " + encryptBASE64(privateKey.getEncoded()));

    }

    public static String encryptBASE64(byte[] key) throws Exception {

        return (new BASE64Encoder()).encodeBuffer(key);

    }
}






