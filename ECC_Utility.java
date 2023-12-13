package com.hpynew.moneyspotatm.encryption;

import static com.hpynew.moneyspotatm.util.KeyValue.key;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


public class ECC_Utility {

    public String publicKeyStr = "";
    public String privateKeyStr = "";

    public void setPublicKey(String publicKeyStr) {
        this.publicKeyStr = publicKeyStr;
    }

    public void setPrivateKey(String privateKeyStr) {
        this.privateKeyStr = privateKeyStr;
    }

    public String encryptData(String message) {
        String encryptedMessage = "";
        try {
            Cipher encryptCipher = Cipher.getInstance("ECIES", "BC");
            encryptCipher.init(Cipher.ENCRYPT_MODE, decodePublicKey(publicKeyStr));
            byte[] encryptedData = encryptCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            encryptedMessage = Base64.encodeToString(encryptedData, Base64.DEFAULT);
        } catch (Exception e) {
            encryptedMessage = "";
            Log.e("TAG", "ECC_encryptData_exp: " + e.getMessage());
        }
        return encryptedMessage;
    }

    public String decryptData(String encryptedMessage) {
        String decryptedMessage = "";
        try {
            Cipher decryptCipher = Cipher.getInstance("ECIES", "BC");
            decryptCipher.init(Cipher.DECRYPT_MODE, decodePrivateKey(privateKeyStr));
            byte[] encryptedBytes = Base64.decode(encryptedMessage, Base64.DEFAULT);
            byte[] decryptedData = decryptCipher.doFinal(encryptedBytes);
            decryptedMessage = new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            decryptedMessage = "";
            Log.e("TAG", "ECC_decryptData_exp: " + e.getMessage());
        }
        return decryptedMessage;
    }






    public String getPublicKeyStr() {
        String value = "";
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(256); // Adjust key size as needed
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            Log.e("TAG", "getPublicKeyStr: " + publicKey);
//            PrivateKey privateKey = keyPair.getPrivate();
            value = encodePublicKey(publicKey);
        } catch (Exception e) {
            value = "";
        }
        return value;
    }

    public String getPrivateKeyStr() {
        String value = "";
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(256); // Adjust key size as needed
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
//            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            Log.e("TAG", "getPrivateKeyStr: " + privateKey);
            value = encodePrivateKey(privateKey);
        } catch (Exception e) {
            value = "";
        }
        return value;
    }





    public String encodePrivateKey(PrivateKey privateKey) {
//        String encodedPrivateKey = Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP);
        String encodedPrivateKey = Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT);
        return encodedPrivateKey;
    }

    public String encodePublicKey(PublicKey publicKey) {
//        String encodedPublicKey = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
        String encodedPublicKey = Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
        return encodedPublicKey;
    }


    public PublicKey decodePublicKey(String publicKeyString)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
//        byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
        byte[] keyBytes = Base64.decode(publicKeyString, Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }

    public PrivateKey decodePrivateKey(String privateKeyString)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
//        byte[] keyBytes = Base64.getDecoder().decode(privateKeyString);
        byte[] keyBytes = Base64.decode(privateKeyString, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        return key;
    }

    public String signMessage(String combinedEncryptedMessage) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        PrivateKey pvtKey = decodePrivateKey(privateKeyStr);
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(pvtKey);
        ecdsaSign.update(combinedEncryptedMessage.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
//        String encodedSignature = Base64.getEncoder().encodeToString(signature);
        String encodedSignature = Base64.encodeToString(signature, Base64.DEFAULT);
        return encodedSignature;
    }

    public boolean verifySignature(String combinedEncryptedMessage, String signature) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
//        byte[] decodedSignature = Base64.getDecoder().decode(signature);
        byte[] decodedSignature = Base64.decode(signature, Base64.DEFAULT);
        PublicKey pubKey = decodePublicKey(publicKeyStr);
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(pubKey);
        ecdsaVerify.update(combinedEncryptedMessage.getBytes("UTF-8"));
        boolean result = ecdsaVerify.verify(decodedSignature);
        return result;
    }

}
