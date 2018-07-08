package ab3.impl.Jahrer_Isopp_Hribar;


import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import ab3.PasswordTools;

public class PasswordTool implements PasswordTools {

	@Override
	public SaltedHash createSaltedHash(String password) {
		
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[32];
		random.nextBytes(salt);
		
		return hashWithSalt(password, salt, "SHA-256"); 		
	}
	
	private SaltedHash hashWithSalt(String password, byte[]salt, String algorithm) {
				
		MessageDigest messageDigest;
		try {
			password += Arrays.toString(salt); 
			messageDigest = MessageDigest.getInstance(algorithm);
			messageDigest.update(password.getBytes());
			return new SaltedHash(messageDigest.digest(), salt);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null; 
		
	}

	@Override
	public boolean checkSaltedHash(String password, SaltedHash hash) {
		SaltedHash testHash = hashWithSalt(password, hash.getSalt(), "SHA-256"); 			
		return Arrays.equals(testHash.getHash(), hash.getHash());
	}

	@Override
	public byte[] PBKDF2(byte[] password, byte[] salt, int iterations, int dkLen) {
		//hLen is the length of the pseudo random fuction in octets 
		int hLen = 160/8; 
		
		
		if (dkLen < 1 || password == null || salt == null || iterations < 1 || 
				//dkLen must be smaller then 2^32-1 * hlen
				dkLen < (Integer.MAX_VALUE * hLen)) 
			return null;
			
		if (dkLen < 20) 
			dkLen = 20; 
		
		
		int l = (int) Math.ceil(dkLen / hLen);
		int r = dkLen - (l - 1) * hLen; 
		
		//Key array 
		byte[][] T = new byte[l][hLen]; 
		
		//Get T1, T2, ..., Tl
		for (int i = 0; i < T.length; i++) { 
			String sPswd = Arrays.toString(password);  
			T[i] = F(sPswd, salt, iterations, i); 
		}
	
		
		//derive key
		byte[] dk = new byte[dkLen]; 
		byte[] tComplete = new byte[l * hLen]; 
		//concatenate T1, T2, ..., Tl
		for(int i = 0, k = 0; i < T.length; i++)
            for(int j = 0; j < T[0].length; j++, k++)
                tComplete[k] = T[i][j];

		System.arraycopy(tComplete, 0, dk, 0, hLen);
		return dk; 
		
	}
	
	private byte[] F(String password, byte[] salt, int iterations, int i) {
		int hLen = 160/8; 
		String algorithm = "SHA-1"; 
		
		//U1 ist on position U[0][0] 
		byte[][] U = new byte[iterations][hLen]; 
		
		//create all U´s
		for (int j = 0; j < U.length; j++) {
			if (j == 0) {
				//first iteration: concatenate INT(i) to salt;
				byte[] concatSalt = new byte[salt.length + 4]; 
				byte[] iByte = new byte[4]; 
				iByte = new BigInteger(String.valueOf(i)).toByteArray();
				System.arraycopy(salt, 0, concatSalt, 0, salt.length);
				System.arraycopy(iByte, 0, concatSalt, salt.length, iByte.length);
				
				U[j] = hashWithSalt(password, concatSalt, algorithm).getHash(); 
			} else {
				//all other iterations: use former U as salt
				U[j] = hashWithSalt(password, U[j-1], algorithm).getHash(); 
			}
				
		}
		
	
		byte[] key = new byte[hLen];
		//fill the key initialy with 0 
		for(byte b : key) {
			b = (byte) 0; 
		}
		
		for (int k = 0; k < U.length; k++) {
			for(int l = 0; l < U[k].length; l++) {
				key[l] = (byte) (key [l] ^ U[k][l]);
			}
		}
		
		return key; 
	}

	@Override
	public byte[] generateRandomBytes(int len, int secLen) {
		
		BigInteger p; 
		BigInteger q; 
		BigInteger sophieGermanP; 
		BigInteger sophieGermanQ; 
		BigInteger n; 
		BigInteger s; 
		
		do {
			p = new BigInteger(secLen/2, 100, new SecureRandom());
			q = new BigInteger(secLen/2, 100, new SecureRandom());
			
			sophieGermanP = p.multiply(new BigInteger("2")).add(BigInteger.ONE);
			sophieGermanQ = q.multiply(new BigInteger("2")).add(BigInteger.ONE); 
			
			n = p.multiply(q);
		} while(p.compareTo(q) == 0 || sophieGermanP.isProbablePrime(100) || 
				sophieGermanQ.isProbablePrime(100) || n.bitLength() != secLen); 	
		
		do {
			s = new BigInteger(64, new SecureRandom()); 
		} while (s.mod(n).equals(BigInteger.ZERO) || s.compareTo(new BigInteger("2")) < 0); 
				
		return blumBlumShub(s, n, len);
	}
	
	private byte[] blumBlumShub(BigInteger s, BigInteger n, int len) {
		s = s.multiply(s).mod(n); 
		
		byte[] longRandom = s.toByteArray(); 
		byte[] random = new byte[len]; 
		
		for (int i = 0; i < len; i++) {
			random[i] = longRandom[i]; 
		}
		
		return random; 
	}

}
