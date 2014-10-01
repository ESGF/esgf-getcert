package esg.security.myproxy;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.asn1.ASN1Sequence;


/**
 * 
 * @author Karem Terry
 *
 */
public class PemUtil {
	
	/** Logger. */
   private static Log LOG = LogFactory.getLog(PemUtil.class);
	private static final String CERTIFICATE_PEM_FOOTER = "-----END CERTIFICATE-----\n";
    private static final String CERTIFICATE_PEM_HEADER = "-----BEGIN CERTIFICATE-----\n";
    private static final String RSA_PRIVATE_KEY_PEM_FOOTER = "-----END RSA PRIVATE KEY-----\n";
    private static final String RSA_PRIVATE_KEY_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----\n";
	
	 /**
     * Get all X509 certificates in pem format of a directory
     * @param directoryPath directory path
     * @throws IllegalArgumentException 
     * @throws CertificateException 
     * @throws IOException 
     */
    public static Collection<X509Certificate> getCAX509Certificates(String directoryPath) throws IllegalArgumentException, CertificateException, IOException{
    	
    	Collection<X509Certificate> certificates=new LinkedList<X509Certificate>();
    	
    	File certDirectory = new File(directoryPath);
    	File[] files = certDirectory.listFiles();
    	if (files != null) { // read all files
    		for (File file : files) {
    			String fileName=file.getName();
    			int index= fileName.lastIndexOf(".");
    			if(index!=-1){
    				//if files is filename.0 type 
    				if(fileName.substring(index+1).equals("0")){
    					try{
    					X509Certificate[] tempCerts=getX509Certificates(pemFileToString(file));
    					certificates.addAll(Arrays.asList(tempCerts));
    					}catch(IllegalArgumentException e){
    						 throw new IllegalArgumentException(e.getMessage()+". "
    					         +"Error reading X509 certificate from: "+ file.getAbsolutePath(),
    					         e.getCause());
    					}
    				}
    			}
    		}
    	}
    	return certificates;
    }
    

    /**
     * Get fragment of PEM
     * 
     * @param pem
     *            PEM formatted data String
     * @param header
     *            DER data header
     * @param footer
     *            DER data footer
     * @return
     * @throws IllegalArgumentException
     *             if the PEM String does not contain the requested data
     */
    private static byte[] getFragmentOfPEM(String pem, String header, String footer) {

        String[] tokens1 = pem.split(header);
        if (tokens1.length < 2) {
            throw new IllegalArgumentException(
                    "The PEM data does not contain the requested header");
        }
        String[] tokens2 = tokens1[1].split(footer);
        tokens2[0] = header + tokens2[0] + footer;

      
        return tokens2[0].getBytes();
    }
    
    /**
     * Convert PKCS#8 format into PKCS#1 format.
     * 
     * @param bytes
     *            bytes of PKCS#8 private key
     * @return byte array of private key in format PKCS#1
     */
    private static byte[] getPKCS1BytesFromPKCS8Bytes(byte[] bytes) {
        /*
         * DER format: http://en.wikipedia.org/wiki/Distinguished_Encoding_Rules
         * PKCS#8: http://tools.ietf.org/html/rfc5208
         */
        int bIndex = 0;

        // Start with PrivateKeyInfo::=SEQUENCE
        // 0x30 Sequence
        if (bytes[bIndex] != 48) {
        	LOG.error("Not a PKCS#8 private key");
            throw new IllegalArgumentException("Not a PKCS#8 private key");
        }

        // next byte contain the number of bytes
        // of SEQUENCE element (length field)
        ++bIndex;

        // Get number of bytes of element
        int sizeOfContent = getSizeOfContent(bytes, bIndex);
        int sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);

        LOG.debug("PrivateKeyInfo(SEQUENCE): Number of bytes:"
                + sizeOfContent
                + "PrivateKeyInfo(SEQUENCE): Number of bytes of length field:"
                + sizeOfLengthField);

        // version::=INTEGER
        // shift index to version element
        bIndex += sizeOfLengthField;

        // 0x02 Integer
        if (bytes[bIndex] != 2) {
        	LOG.error("Not a PKCS#8 private key");
            throw new IllegalArgumentException("Not a PKCS#8 private key");
        }
        ++bIndex;

        // Get number of bytes of element
        sizeOfContent = getSizeOfContent(bytes, bIndex);
        sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);

        LOG.debug("Version(INTEGER): Number of bytes:" + sizeOfContent
                + "Version(INTEGER): Number of bytes of length field:"
                + sizeOfLengthField);

        // PrivateKeyAlgorithm::= PrivateKeyAlgorithmIdentifier
        // shift index to PrivateKeyAlgorithm element
        bIndex = bIndex + sizeOfLengthField + sizeOfContent;

        // ? PrivateKeyAlgorithmIdentifier
        // if (bytes[bIndex] != ?) {
        // throw new IllegalArgumentException("Not a PKCS#8 private key");
        // }

        ++bIndex;

        // Get number of bytes of element
        sizeOfContent = getSizeOfContent(bytes, bIndex);
        sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);
        LOG.debug("PrivateKeyAlgorithm(PrivateKeyAlgorithmIdentifier): Number of bytes:"
                + sizeOfContent
                + "PrivateKeyAlgorithm(PrivateKeyAlgorithmIdentifier): "
                + "Number of bytes of length field:" + sizeOfLengthField);

        // PrivateKey::= OCTET STRING
        // shift index to PrivateKey element
        bIndex = bIndex + sizeOfLengthField + sizeOfContent;

        // 0x04 OCTET STRING
        if (bytes[bIndex] != 4) {
            throw new IllegalArgumentException("Not a PKCS#8 private key");
        }
        ++bIndex;

        // Get number of bytes of element
        sizeOfContent = getSizeOfContent(bytes, bIndex);
        sizeOfLengthField = getSizeOfLengthField(bytes, bIndex);

        LOG.debug("PrivateKey(OCTET STRING: Number of bytes:"
                + sizeOfContent
                + "PrivateKey(OCTET STRING): Number of bytes of length field:"
                + sizeOfLengthField);

        return Arrays.copyOfRange(bytes, bIndex + sizeOfLengthField, bIndex
                + sizeOfLengthField + sizeOfContent);
    }
    
    /**
     * Read RSA private key from pem and returns {@link PrivateKey}
     * 
     * @param pem in String format
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
	public static PrivateKey getPrivateKey(String pem) throws IOException, GeneralSecurityException {
	
		PrivateKey key = null;

            byte[] bytes = getFragmentOfPEM(pem, RSA_PRIVATE_KEY_PEM_HEADER,
                    RSA_PRIVATE_KEY_PEM_FOOTER);

            String rsa = new String(bytes);
            String split[] = rsa.split("-----");
            rsa = split[2];

            ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence
                    .fromByteArray(Base64.decode(rsa.getBytes()));

            Enumeration<?> e = primitive.getObjects();
            BigInteger v = ((DERInteger) e.nextElement()).getValue();

            int version = v.intValue();
            if (version != 0 && version != 1) {
                throw new IllegalArgumentException(
                        "wrong version for RSA private key");
            }
            /**
             * In fact only modulus and private exponent are in use.
             */
            BigInteger modulus = ((DERInteger) e.nextElement()).getValue();
            BigInteger publicExponent = ((DERInteger) e.nextElement())
                    .getValue();
            BigInteger privateExponent = ((DERInteger) e.nextElement())
                    .getValue();
            BigInteger prime1 = ((DERInteger) e.nextElement()).getValue();
            BigInteger prime2 = ((DERInteger) e.nextElement()).getValue();
            BigInteger exponent1 = ((DERInteger) e.nextElement()).getValue();
            BigInteger exponent2 = ((DERInteger) e.nextElement()).getValue();
            BigInteger coefficient = ((DERInteger) e.nextElement()).getValue();

            RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(modulus,
                    privateExponent);
            try{
            	KeyFactory kf = KeyFactory.getInstance("RSA");
            	key = kf.generatePrivate(rsaPrivKeySpec);
            }catch(GeneralSecurityException e1){
            	throw e1;
            }

        return key;
    }

    /**
     * Get remaining time of certificate in milliseconds, after this time it
     * will be invalid.
     * 
     * @param pem
     * @return remaining time of certificate in milliseconds
     * @throws CertificateException if error happens reading X509 certificate in pem
     */
    public static long getRemainTimeOfCredentialsInMillis(String pem) throws CertificateException{
    	 X509Certificate cert = getX509UserCertificate(pem);
         Date expireDate = cert.getNotAfter();
         Date currentDate = new Date();

         // Calculate difference in milliseconds
         // getdate() returns the number of milliseconds since
         // January 1, 1970
         long diffTime = expireDate.getTime() - currentDate.getTime();
         return diffTime;
    }
    
	/**
     * Get size of "content" of PKCS8 element
     * @param bytes
     * @param bIndex
     * @return
     */
    private static int getSizeOfContent(byte[] bytes, int bIndex) {
        byte aux = bytes[bIndex];

        if ((aux & 0x80) == 0) { // applies mask
            // short form
            return aux;
        }

        /*
         * long form: if first bit begins with 1 then the rest of bits are the
         * number of bytes that contain the number of bytes of element 375 is
         * 101110111 then in 2 bytes: 00000001 01110111 that is the number of
         * bytes that contain the number of bytes ex: 375 is 101110111 then in 2
         * bytes: 00000001 01110111 .
         */
        byte numOfBytes = (byte) (aux & 0x7F);

        if (numOfBytes * 8 > 32) {
            throw new IllegalArgumentException("ASN.1 field too long");
        }

        int contentLength = 0;

        // find out the number of bits in the bytes
        for (int i = 0; i < numOfBytes; ++i) {
            contentLength = (contentLength << 8) + bytes[(bIndex + 1 + i)];
        }

        return contentLength;
    }
    
    /**
     * Get size of "length field" of PKCS8 element
     * @param bytes
     * @param bIndex
     * @return
     */
    private static int getSizeOfLengthField(byte[] bytes, int bIndex) {
        byte aux = bytes[bIndex];

        if ((aux & 0x80) == 0) { // applies mask
            return 1; // short form
        }
        return ((aux & 0x7F) + 1); // long form
    }

    /**
     * Read certificates from pem and returns array of certificates
     * 
     * @param pem
     * @return array of {@link X509Certificate}
     * @throws CertificateException
     */
    public static X509Certificate[] getX509Certificates(String pem)
            throws CertificateException {
    	
        CertificateFactory certFactory = CertificateFactory
                .getInstance("X.509");

        String[] tokens1 = pem.split(CERTIFICATE_PEM_HEADER);
        if (tokens1.length < 2) {
            throw new IllegalArgumentException(
                    "The PEM data does not contain the requested header");
        }

        int certNumber = tokens1.length - 1;

        X509Certificate[] certificates = new X509Certificate[certNumber];

        // first is the user cert
        String[] tokens2 = tokens1[1].split(CERTIFICATE_PEM_FOOTER);
        tokens2[0] = CERTIFICATE_PEM_HEADER + tokens2[0]
                + CERTIFICATE_PEM_FOOTER;
        InputStream in = new ByteArrayInputStream(tokens2[0].getBytes());
        certificates[0] = (X509Certificate) certFactory.generateCertificate(in);

        for (int i = 2; i < tokens1.length; i++) {
            tokens2 = tokens1[i].split(CERTIFICATE_PEM_FOOTER);
            tokens2[0] = CERTIFICATE_PEM_HEADER + tokens2[0]
                    + CERTIFICATE_PEM_FOOTER;
            in = new ByteArrayInputStream(tokens2[0].getBytes());
            certificates[i - 1] = (X509Certificate) certFactory
                    .generateCertificate(in);
        }
        
        return certificates;
    }
    

    /**
     * Read user certificate from pem
     * 
     * @param pem
     * @return
     * @throws CertificateException
     */
    public static X509Certificate getX509UserCertificate(String pem) throws CertificateException{
       
        
    	X509Certificate x509Certificate = null;

    	// Credential.pem have RSA key and certificate in the same file
    	// and must be splitted

    	byte[] bytes = getFragmentOfPEM(pem, CERTIFICATE_PEM_HEADER,
    			CERTIFICATE_PEM_FOOTER);

    	CertificateFactory certFactory = CertificateFactory
    			.getInstance("X.509");
    	InputStream in = new ByteArrayInputStream(bytes);
    	x509Certificate = (X509Certificate) certFactory
    			.generateCertificate(in);

	
    	return x509Certificate;
    }
    
    /**
     * Reads the contents of a file and return it in a String format.
     * 
     * @param pemFile
     *            pem file to be read
     * @return pem in String format
     * @throws IOException
     *             if the file could not be read
     */
    private static String pemFileToString(File pemFile) throws IOException {

        BufferedReader reader = new BufferedReader(new FileReader(
        		pemFile));
        StringBuffer sb = new StringBuffer();
        String line = reader.readLine();
        while (line != null) {
            sb.append(line);
            sb.append("\n");
            line = reader.readLine();
        }
        reader.close();
        return sb.toString();
    }


    /**
     * Write bytes encoded in base 64 into output stream
     * 
     * @param bytes
     *            to encoded
     * @param out
     *            output stream of bytes
     * @throws IOException
     *             if an I/O error occurs.
     */
    private static void writeBASE64(byte[] bytes, OutputStream out) throws IOException {
    	LOG.debug("Encoding in base64...");
        byte[] arrayOfByte = Base64.encode(bytes);
        for (int i = 0; i < arrayOfByte.length; i += 64) {
            if (arrayOfByte.length - i > 64) {
                out.write(arrayOfByte, i, 64);
            } else {
                out.write(arrayOfByte, i, arrayOfByte.length - i);
            }
            out.write("\n".getBytes());
        }
    }

    /**
     * Write CA certificates of a directory in pem file
     * @param ous file output stream
     * @param directoryPath directory 
     * @throws IOException 
     * @throws CertificateException 
     */
    public static void writeCACertificate(FileOutputStream ous, String directoryPath) throws IOException, CertificateException{
    	Collection<X509Certificate> cacerts=getCAX509Certificates(directoryPath);
    	Iterator<X509Certificate> iter = cacerts.iterator();
    	
    	// Write x509 certificates 
        for (int i = 0; i < cacerts.size(); i++) {
            X509Certificate cert = iter.next();
            LOG.debug("certificate["+i+"]:"+cert);
            LOG.debug("Writing certificate number"+i+"...");
            ous.write(CERTIFICATE_PEM_HEADER.getBytes());
            writeBASE64(cert.getEncoded(), ous);
            ous.write(CERTIFICATE_PEM_FOOTER.getBytes());
        }
    	
    	ous.close();
    }
    /**
     * Write credentials in pem format
     * @param ous output stream
     * @param x509Certificates where the first certificate is the user certificate
     * @param key RSA private key
     * @throws IOException
     * @throws CertificateEncodingException
     */
	public static void writeCredentials(OutputStream ous, 
			Collection<X509Certificate> x509Certificates, PrivateKey key) 
					throws IOException, CertificateEncodingException {	
		
		Iterator<X509Certificate> iter = x509Certificates.iterator();

        LOG.debug("Writing x509 certificate in pem format...");
        ous.write(CERTIFICATE_PEM_HEADER.getBytes());
        writeBASE64(iter.next().getEncoded(), ous);
        ous.write(CERTIFICATE_PEM_FOOTER.getBytes());

        LOG.debug("Transforming ASN.1 PKCS#8 private key to ASN1PKCS#1 format...");
        byte[] bytes = getPKCS1BytesFromPKCS8Bytes(key.getEncoded());

        LOG.debug("Writing rsa private key in pem format...");
        ous.write(RSA_PRIVATE_KEY_PEM_HEADER.getBytes());
        writeBASE64(bytes, ous);
        ous.write(RSA_PRIVATE_KEY_PEM_FOOTER.getBytes());


        // Write another x509 certificates if exists
        for (int i = 1; i < x509Certificates.size(); i++) {
            X509Certificate cert = iter.next();
            LOG.debug("certificate["+i+"]:"+cert);
            LOG.debug("Writing certificate number "+i+"...");
            ous.write(CERTIFICATE_PEM_HEADER.getBytes());
            writeBASE64(cert.getEncoded(), ous);
            ous.write(CERTIFICATE_PEM_FOOTER.getBytes());
        }

        ous.close();
		
	}

}


