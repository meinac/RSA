package com.rsa.example;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

public class Main {
	
	public static void write(String fileName, BigInteger modulus, BigInteger exponent){
		try {
			ObjectOutputStream oout = new ObjectOutputStream(
		            new BufferedOutputStream(new FileOutputStream(fileName)));
			oout.writeObject(modulus);
			oout.writeObject(exponent);
			oout.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static PublicKey readPublic(String fileName){
		InputStream in;
		try {
			in = new FileInputStream(fileName);
			ObjectInputStream oin =
		            new ObjectInputStream(new BufferedInputStream(in));
			BigInteger modulus = (BigInteger) oin.readObject();
			BigInteger exponent = (BigInteger) oin.readObject();
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
	        KeyFactory fact = KeyFactory.getInstance("RSA");
	        PublicKey pubKey = fact.generatePublic(keySpec);
	        return pubKey;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static PrivateKey readPrivate(String fileName){
		InputStream in;
		try {
			in = new FileInputStream(fileName);
			ObjectInputStream oin =
		            new ObjectInputStream(new BufferedInputStream(in));
			BigInteger modulus = (BigInteger) oin.readObject();
			BigInteger exponent = (BigInteger) oin.readObject();
			RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, exponent);
	        KeyFactory fact = KeyFactory.getInstance("RSA");
	        PrivateKey privateKey = fact.generatePrivate(keySpec);
	        return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args) {
		String string = "Hello";
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp = kpg.genKeyPair();
			Key publicKey = kp.getPublic();
            Key privateKey = kp.getPrivate();
            
            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pub = (RSAPublicKeySpec) fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec priv = (RSAPrivateKeySpec) fact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherData = cipher.doFinal(string.getBytes());
            System.out.println(new String(cipherData));
            
            write("public_key", pub.getModulus(), pub.getPublicExponent());
            write("private_key", priv.getModulus(), priv.getPrivateExponent());
            
            Key privateK = readPrivate("private_key");
            
            cipher.init(Cipher.DECRYPT_MODE, privateK);
            byte[] newCipherData = cipher.doFinal(cipherData);
            System.out.println(new String(newCipherData));
            
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
