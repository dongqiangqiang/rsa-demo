package com;

import com.utils.RSAUtil;
import org.apache.commons.codec.binary.Base64;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author dengkunpeng
 * @description rsa utils
 * @create 2018-04-03 09:47
 **/
public class RsaService {

    /**
     * 获得rsa加密字符串
     *
     * @param publicKeyStr
     * @param content
     * @return
     * @throws Exception
     */
    public String encrypt(String publicKeyStr, String content) {
        try {
            RSAPublicKey publicKey = RSAUtil.loadPublicKey(publicKeyStr);
            byte[] buffer = RSAUtil.encrypt(publicKey, content);
            return Base64.encodeBase64String(buffer);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 解密
     *
     * @param privateKeyStr 私钥
     * @param content       密文数据
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public String decrypt(String privateKeyStr, String content) {
        try {
            RSAPrivateKey privateKey = RSAUtil.loadPrivateKey(privateKeyStr);
            byte[] buffer = Base64.decodeBase64(content);
            return new String(RSAUtil.decrypt(privateKey, buffer));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * RSA验签--并用base64加密
     *
     * @param content 签名原文
     * @param sign    待验证签名
     * @return 验签结果
     * @throws Exception
     */
    public boolean verifyBySign(String publicKey, String content, String sign, String signKey) {
        try {
            RSAPublicKey rsaPublicKey = RSAUtil.loadPublicKey(publicKey);
            Signature signature = Signature.getInstance("SHA1WithRSA");
            signature.initVerify(rsaPublicKey);
            signature.update(Base64.decodeBase64(content + signKey));
            return signature.verify(Base64.decodeBase64(sign));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


}
