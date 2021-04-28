package com.inspur.encrypt.sign.demo;

import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * <p>@className EncryptSignDemo</p>
 * <p>@description 加密签名Demo</p>
 */
public class EncryptSignDemo {


    public static void main(String[] args) throws NoSuchAlgorithmException {

        // 1 准备业务参数与密钥
        // 1.1 业务参数文本
        String content = "{\"ai\":\"test-accountId\",\"name\":\"用户姓名\",\"idNum\":\"371321199012310912\"}";
        // 1.2 密钥
        String secretKey = "2836e95fcd10e04b0069bb1ee659955b";
        // 1.3 处理密钥（将16进制字符串密钥转换为byte数组）
        byte[] keyBytes = hexStringToByte(secretKey);

        // 2 业务参数加密（AES-128/GCM + BASE64算法加密）计算
        String encryptStr = aesGcmEncrypt(content, keyBytes);
        System.out.println("业务参数加密结果：" + encryptStr);
//        // 解密
//        String decryptStr = aesGcmDecrypt(encryptStr, keyBytes);
//        System.out.println("业务参数解密结果：" + decryptStr);

        // 3 签名
        /*
         * 签名规则：1 将除去sign的系统参数和除去请求体外的业务参数，根据参数的key进行字典排序，并按照Key-Value的格式拼接成一个字符串。将请求体中的参数拼接在字符串最后。
         *          2 将secretKey拼接在步骤1获得字符串最前面，得到待加密字符串。
         *          3 使用SHA256算法对待加密字符串进行计算，得到数据签名。
         *          4 将得到的数据签名赋值给系统参数sign。
         */
        // 3.1 拼接待签名字符串（下方示例代码中相应字符串均为写死，仅用于参考拼接流程，具体请参照实际接口参数）
        StringBuilder sb = new StringBuilder();
        // 3.1.1 拼接密钥
        sb.append(secretKey);
        // 3.1.2 拼接除去sign的系统参数和除去请求体外的业务参数（含请求URL中的参数，例如get请求。注意需要字典排序）
        sb.append("appIdtest-appIdbizIdtest-bizIdidtest-idnametest-nametimestamps1584949895758");
        // 3.1.3 拼接请求体（保持json字符串格式，data对应的值应为上方加密算法计算出的encryptStr加密字符串）
        sb.append("{\"data\":\"CqT/33f3jyoiYqT8MtxEFk3x2rlfhmgzhxpHqWosSj4d3hq2EbrtVyx2aLj565ZQNTcPrcDipnvpq/D/vQDaLKW70O83Q42zvR0//OfnYLcIjTPMnqa+SOhsjQrSdu66ySSORCAo\"}");

        String toBeSignStr = sb.toString();
        System.out.println("待签名字符串：" + toBeSignStr);

        // 3.1 签名计算（SHA256）
        String sign = sign(toBeSignStr);
        System.out.println("签名结果：" + sign);

    }

    /**
     * <p>@title sign</p>
     * <p>@description 签名</p>
     *
     * @param toBeSignStr 待签名字符串
     * @return java.lang.String
     */
    private static String sign(String toBeSignStr) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(toBeSignStr.getBytes(UTF_8));
        return byteToHexString(messageDigest.digest());
    }

    /**
     * <p>@title aesGcmEncrypt</p>
     * <p>@description Aes-Gcm加密</p>
     *
     * @param content 待加密文本
     * @param key     密钥
     * @return java.lang.String
     */
    private static String aesGcmEncrypt(String content, byte[] key) {
        try {
            // 根据指定算法ALGORITHM自成密码器
            Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
            SecretKeySpec skey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, skey);
            //获取向量
            byte[] ivb = cipher.getIV();
            byte[] encodedByteArray = cipher.doFinal(content.getBytes(UTF_8));
            byte[] message = new byte[ivb.length + encodedByteArray.length];
            System.arraycopy(ivb, 0, message, 0, ivb.length);
            System.arraycopy(encodedByteArray, 0, message, ivb.length, encodedByteArray.length);
            return Base64.getEncoder().encodeToString(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            //建议自行调整为日志输出或抛出异常
            return null;
        }
    }

    /**
     * <p>@title aesGcmDecrypt</p>
     * <p>@description Aes-Gcm解密</p>
     *
     * @param content 带解密文本
     * @param key     密钥
     * @return java.lang.String
     */
    private static String aesGcmDecrypt(String content, byte[] key) {
        try {
            // 根据指定算法ALGORITHM自成密码器
            Cipher decryptCipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
            SecretKeySpec skey = new SecretKeySpec(key, "AES");
            byte[] encodedArrayWithIv = Base64.getDecoder().decode(content);
            GCMParameterSpec decryptSpec = new GCMParameterSpec(128, encodedArrayWithIv, 0, 12);
            decryptCipher.init(Cipher.DECRYPT_MODE, skey, decryptSpec);
            byte[] b = decryptCipher.doFinal(encodedArrayWithIv, 12, encodedArrayWithIv.length - 12);
            return new String(b, UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException | InvalidAlgorithmParameterException e) {
            //建议自行调整为日志输出或抛出异常
            return null;
        }
    }

    /**
     * <p>@title byteToHexString</p>
     * <p>@description byte数组转化为16进制字符串</p>
     *
     * @param bytes byte数组
     * @return java.lang.String
     */
    private static String byteToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            String strHex = Integer.toHexString(aByte);
            if (strHex.length() > 3) {
                sb.append(strHex.substring(6));
            } else {
                if (strHex.length() < 2) {
                    sb.append("0").append(strHex);
                } else {
                    sb.append(strHex);
                }
            }
        }
        return sb.toString();
    }

    /**
     * <p>@title hexStringToByte</p>
     * <p>@description 十六进制string转二进制byte[]</p>
     *
     * @param str 十六进制字符串
     * @return byte[]
     */
    private static byte[] hexStringToByte(String str) {
        byte[] baKeyword = new byte[str.length() / 2];
        for (int i = 0; i < baKeyword.length; i++) {
            try {
                baKeyword[i] = (byte) (0xff & Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16));
            } catch (Exception e) {
                //建议自行调整为日志输出或抛出异常
                e.printStackTrace();
            }
        }
        return baKeyword;
    }
}
