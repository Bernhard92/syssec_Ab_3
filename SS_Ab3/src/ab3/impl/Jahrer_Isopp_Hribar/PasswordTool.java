package ab3.impl.Jahrer_Isopp_Hribar;


import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import ab3.PasswordTools;

public class PasswordTool implements PasswordTools {

	@Override
	public SaltedHash createSaltedHash(String password) {
		
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[32];
		random.nextBytes(salt);
		
		return hashWithSalt(password, salt); 		
	}
	
	private SaltedHash hashWithSalt(String password, byte[]salt) {
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 5, 256);
			SecretKey secretKey = skf.generateSecret(spec);

			return new SaltedHash(secretKey.getEncoded(), salt); 
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		} 
		return null;
		
	}

	@Override
	public boolean checkSaltedHash(String password, SaltedHash hash) {
		SaltedHash testHash = hashWithSalt(password, hash.getSalt()); 			
		return Arrays.equals(testHash.getHash(), hash.getHash());
	}

	@Override
	public byte[] PBKDF2(byte[] password, byte[] salt, int iterations, int dkLen) {
		
		
		return null;
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
