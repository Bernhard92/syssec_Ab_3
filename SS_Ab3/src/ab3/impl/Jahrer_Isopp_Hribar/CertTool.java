package ab3.impl.Jahrer_Isopp_Hribar;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;


import ab3.CertTools;

public class CertTool implements CertTools{
	

	private final int DEFAULPORT = 443; 
	private X509Certificate[] certificates; 
	

	@Override
	public boolean loadServerCerts(String host, Integer port) {
		if (port == null) 
			port = DEFAULPORT; 
		
		System.out.println("Downloading certificate from: " + host + " on port: " + port);
		
		try {
			//takes protocol, host, port and the file on the host
			URL url = new URL("https", host, port, "/");
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection(); 
			connection.connect();
			certificates = (X509Certificate[]) connection.getServerCertificates(); 
		} catch (IOException e) {
			System.out.println("Error connecting to server");
			e.printStackTrace();
		} 
	
		return true;
	}
	
	
	@Override
	public void setCerts(Set<X509Certificate> certs) {
		certificates = certs.toArray(new X509Certificate[certs.size()]); 
	}

	@Override
	public int getNumberCerts() {
		return certificates.length; 
	}

	@Override
	public String getCertRepresentation(int cert) {
		try {
            return  Base64.getEncoder().encodeToString(certificates[cert].getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            e.printStackTrace();
        }
        return  null;
	}

	@Override
	public String getPublicKey(int cert) {
		return Base64.getEncoder().encodeToString(certificates[cert].getPublicKey().getEncoded());
	}

	@Override
	public String getSignatureAlgorithmName(int cert) {
		return certificates[cert].getSigAlgName(); 
	}

	@Override
	public String getSubjectDistinguishedName(int cert) {
		return certificates[cert].getSubjectDN().getName(); 
	}

	@Override
	public String getIssuerDistinguishedName(int cert) {
		return certificates[cert].getIssuerDN().getName(); 
	}

	@Override
	public Date getValidFrom(int cert) {
		return certificates[cert].getNotBefore(); 
	}

	@Override
	public Date getValidUntil(int cert) {
		return certificates[cert].getNotAfter(); 
	}

	@Override
	public String getSerialNumber(int cert) {
		return certificates[cert].getSerialNumber().toString(16);
	}

	@Override
	public String getIssuerSerialNumber(int cert) {
		//is the cert the root cert
		if (cert < certificates.length -2) {
			return getSerialNumber(cert + 1); 
		} else {
			return getSerialNumber(certificates.length-1); 
		} 
		
	}

	@Override
	public String getSignature(int cert) {
		return Base64.getEncoder().encodeToString(certificates[cert].getSignature()); 
	}

	@Override
	public String getSHA1Fingerprint(int cert) {
		return getSHAFingerprint(cert, "SHA-1"); 
	}

	@Override
	public String getSHA256Fingerprint(int cert) {
		return getSHAFingerprint(cert, "SHA-256"); 
	}
	
	private String getSHAFingerprint(int cert, String shaVersion) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(shaVersion);
			messageDigest.update(certificates[cert].getEncoded());
			byte[] sha = messageDigest.digest(); 
			 
			StringBuilder stringBuilder = new StringBuilder(); 
			for (byte b : sha) {
				stringBuilder.append(String.format("%02x", b)); 
			}
			return stringBuilder.toString().toUpperCase(); 
		} catch (NoSuchAlgorithmException | CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null; 
	}

	@Override
	public boolean isForDigitalSignature(int cert) {
		return certificates[cert].getKeyUsage()[0];
	}

	@Override
	public boolean isForKeyEncipherment(int cert) {
		return certificates[cert].getKeyUsage()[2];
	}

	@Override
	public boolean isForKeyCertSign(int cert) {
		return certificates[cert].getKeyUsage()[5];
	}

	@Override
	public boolean isForCRLSign(int cert) {
		return certificates[cert].getKeyUsage()[6];
	}

	@Override
	public boolean verifyAllCerts() {
		
		//check dif all certificate dates are valid
		try {
			for(X509Certificate cert : certificates) {
				cert.checkValidity();
			}
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			e.printStackTrace();
		}
		
		//check if the sigantures are valid
		for (int i = certificates.length-2; i >= 0; i--) {
			try {
				certificates[i].verify(certificates[i+1].getPublicKey());
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (CertificateException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			} catch (SignatureException e) {
				e.printStackTrace();
			}		
		}
	
		return true;
	}

	@Override
	public int getIsserCertNumber(int cert) {
		boolean[] iUID = certificates[cert].getIssuerUniqueID(); 
		String binary = ""; 
		
		if (iUID == null) {
			//the iUID is not in the certificate
			return -1; 
		} else {
			for (boolean b : iUID) {
				if (b) {
					binary += 0; 
				} else {
					binary += 1; 
				}
			}
		}
		
		return Integer.parseInt(binary); 
	}

	@Override
	public List<Integer> getCertificateChain() {
		 List<Integer> chain = new ArrayList<Integer>();
		      
		 for (int i = 0; i < certificates.length; i++) {
	            chain.add(i);
	     }
		 return chain;
	}

}
