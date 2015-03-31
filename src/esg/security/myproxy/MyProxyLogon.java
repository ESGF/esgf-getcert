/*
 * Forked from MyProxy Logon by MyProxy team.
 * See http://grid.ncsa.illinois.edu/myproxy/license.html
 */

package esg.security.myproxy;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.LICENSE;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

/**
 * The MyProxyLogon class provides an interface for retrieving credentials from
 * a MyProxy server.
 */
public class MyProxyLogon {
    static Logger logger = Logger.getLogger(MyProxyLogon.class.getName());
    public static final String version = "1.1";
    public static final String BouncyCastleLicense = LICENSE.licenseText;

    protected static final int keySize = 1024;
    protected final int MIN_PASS_PHRASE_LEN = 6;
    protected static final String keyAlg = "RSA";
    protected static final String pkcs10SigAlgName = "SHA1withRSA";
    protected static final String pkcs10Provider = "SunRsaSign";
    protected State state = State.READY;
    protected String host = "localhost";
    protected String username;
    protected String credname;
    protected String passphrase;
    protected int port = 7512;
    protected int lifetime = 43200;
    protected boolean requestTrustRoots = false;
    protected SSLSocket socket;
    protected BufferedInputStream socketIn;
    protected BufferedOutputStream socketOut;
    protected KeyPair keypair;
    protected Collection certificateChain;
    protected String[] trustrootFilenames;
    protected String[] trustrootData;
    KeyManagerFactory keyManagerFactory;
    private boolean bootstrap;

    /**
     * Constructs a MyProxyLogon object.
     */
    public MyProxyLogon() {
        if (this.host == null) {
            this.host = "localhost";
        }
        String str = System.getenv("MYPROXY_SERVER_PORT");
        if (str != null) {
            this.port = Integer.parseInt(str);
        }
        this.username = System.getProperty("user.name");
        this.bootstrap = false;
    }

    /**
     * Gets the hostname of the MyProxy server.
     *
     * @return MyProxy server hostname
     */
    public String getHost() {
        return this.host;
    }

    /**
     * Sets the hostname of the MyProxy server. Defaults to localhost.
     *
     * @param host
     *            MyProxy server hostname
     */
    public void setHost(String paramString) {
        this.host = paramString;
    }

    /**
     * Gets the port of the MyProxy server.
     *
     * @return MyProxy server port
     */
    public int getPort() {
        return this.port;
    }

    /**
     * Sets the port of the MyProxy server. Defaults to 7512.
     *
     * @param port
     *            MyProxy server port
     */
    public void setPort(int paramInt) {
        this.port = paramInt;
    }

    /**
     * Gets the MyProxy username.
     *
     * @return MyProxy server port
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * Sets the MyProxy username. Defaults to user.name.
     *
     * @param username
     *            MyProxy username
     */
    public void setUsername(String paramString) {
        this.username = paramString;
    }

    /**
     * Gets the optional MyProxy credential name.
     *
     * @return credential name
     */
    public String getCredentialName() {
        return this.credname;
    }

    /**
     * Sets the optional MyProxy credential name.
     *
     * @param credname
     *            credential name
     */
    public void setCredentialName(String paramString) {
        this.credname = paramString;
    }

    /**
     * Sets the MyProxy passphrase.
     *
     * @param passphrase
     *            MyProxy passphrase
     */
    public void setPassphrase(String paramString) {
        this.passphrase = paramString;
    }

    /**
     * Gets the requested credential lifetime.
     *
     * @return Credential lifetime
     */
    public int getLifetime() {
        return this.lifetime;
    }

    /**
     * Sets the requested credential lifetime. Defaults to 43200 seconds (12
     * hours).
     *
     * @param seconds
     *            Credential lifetime
     */
    public void setLifetime(int paramInt) {
        this.lifetime = paramInt;
    }

    /**
     * Gets the certificates returned from the MyProxy server by
     * getCredentials().
     *
     * @return Collection of certificate objects
     */
    public Collection getCertificates() {
        return this.certificateChain;
    }

    /**
     * Gets the private key generated by getCredentials().
     *
     * @return PrivateKey
     */
    public PrivateKey getPrivateKey() {
        return this.keypair.getPrivate();
    }

    /**
     * Sets whether to request trust roots (CA certificates, CRLs, signing
     * policy files) from the MyProxy server. Defaults to false (i.e., not
     * to request trust roots).
     *
     * @param flag
     *            If true, request trust roots. If false, don't request trust
     *            roots.
     */
    public void requestTrustRoots(boolean paramBoolean) {
        this.requestTrustRoots = paramBoolean;
    }

    /**
     * Gets trust root filenames.
     *
     * @return trust root filenames
     */
    public String[] getTrustRootFilenames() {
        return this.trustrootFilenames;
    }

    /**
     * Gets trust root data corresponding to the trust root filenames.
     *
     * @return trust root data
     */
    public String[] getTrustRootData() {
        return this.trustrootData;
    }

    /**
     * Connects to the MyProxy server at the desired host and port. Requires
     * host authentication via SSL. The host's certificate subject must
     * match the requested hostname. If CA certificates are found in the
     * standard GSI locations, they will be used to verify the server's
     * certificate. If trust roots are requested and no CA certificates are
     * found, the server's certificate will still be accepted.
     */
    public void connect() throws IOException, GeneralSecurityException {
        SSLContext localSSLContext = SSLContext.getInstance("TLS");
        TrustManager[] arrayOfTrustManager = { new MyTrustManager() };
        localSSLContext.init(getKeyManagers(), arrayOfTrustManager,
                new SecureRandom());
        SSLSocketFactory localSSLSocketFactory = localSSLContext
                .getSocketFactory();
        this.socket = ((SSLSocket) localSSLSocketFactory.createSocket(
                this.host, this.port));
        this.socket.setEnabledProtocols(new String[] { "TLSv1" });

        this.socket.startHandshake();

        this.socketIn = new BufferedInputStream(this.socket.getInputStream());
        this.socketOut = new BufferedOutputStream(this.socket.getOutputStream());
        this.state = State.CONNECTED;
    }

    /**
     * Get the key manager factory set by setKeyManagerFactory().
     *
     * @return KeyManagerFactory
     */
    public KeyManagerFactory getKeyManagerFactory() {
        return this.keyManagerFactory;
    }

    /**
     * Set the key manager factory for use in client-side SSLSocket
     * certificate-based authentication to the MyProxy server.
     * Call this before connect().
     *
     * @param keyManagerFactory
     *            Key manager factory to use
     */
    public void setKeyManagerFactory(KeyManagerFactory paramKeyManagerFactory) {
        this.keyManagerFactory = paramKeyManagerFactory;
    }

    /**
     * Internal method that returns the KeyManagers for a KeyManagerFactory or a
     * null if no KeyManagerFactory is set.
     *
     * @return
     */
    KeyManager[] getKeyManagers() {
        if (getKeyManagerFactory() == null) {
            return null;
        }
        return getKeyManagerFactory().getKeyManagers();
    }

    /**
     * Disconnects from the MyProxy server.
     */
    public void disconnect() throws IOException {
        this.socket.close();
        this.socket = null;
        this.socketIn = null;
        this.socketOut = null;
        this.state = State.READY;
    }

    /**
     * Logs on to the MyProxy server by issuing the MyProxy GET command.
     */
    public void logon() throws IOException, GeneralSecurityException {
        if (this.state != State.CONNECTED) {
            connect();
        }
        this.socketOut.write(48);
        this.socketOut.flush();
        this.socketOut.write("VERSION=MYPROXYv2".getBytes());
        this.socketOut.write(10);
        this.socketOut.write("COMMAND=0".getBytes());
        this.socketOut.write(10);
        this.socketOut.write("USERNAME=".getBytes());
        this.socketOut.write(this.username.getBytes());
        this.socketOut.write(10);
        this.socketOut.write("PASSPHRASE=".getBytes());
        this.socketOut.write(this.passphrase.getBytes());
        this.socketOut.write(10);
        this.socketOut.write("LIFETIME=".getBytes());
        this.socketOut.write(Integer.toString(this.lifetime).getBytes());
        this.socketOut.write(10);
        if (this.credname != null) {
            this.socketOut.write("CRED_NAME=".getBytes());
            this.socketOut.write(this.credname.getBytes());
            this.socketOut.write(10);
        }
        if (this.requestTrustRoots) {
            this.socketOut.write("TRUSTED_CERTS=".getBytes());
            this.socketOut.write("1\n".getBytes());
        }
        this.socketOut.flush();
        String str1 = readLine(this.socketIn);
        if (str1 == null) {
            throw new EOFException();
        }
        if (!str1.equals("VERSION=MYPROXYv2")) {
            throw new ProtocolException("bad MyProxy protocol VERSION string: "
                    + str1);
        }
        str1 = readLine(this.socketIn);
        if (str1 == null) {
            throw new EOFException();
        }
        if ((!str1.startsWith("RESPONSE="))
                || (str1.length() != "RESPONSE=".length() + 1)) {
            throw new ProtocolException(
                    "bad MyProxy protocol RESPONSE string: " + str1);
        }
        int i = str1.charAt("RESPONSE=".length());
        Object localObject;
        if (i == 49) {
            localObject = new StringBuffer("MyProxy logon failed");
            while ((str1 = readLine(this.socketIn)) != null) {
                if (str1.startsWith("ERROR=")) {
                    ((StringBuffer) localObject).append('\n');
                    ((StringBuffer) localObject).append(str1.substring("ERROR="
                            .length()));
                }
            }
            throw new FailedLoginException(
                    ((StringBuffer) localObject).toString());
        }
        if (i == 50) {
            throw new ProtocolException(
                    "MyProxy authorization RESPONSE not implemented");
        }
        if (i != 48) {
            throw new ProtocolException(
                    "unknown MyProxy protocol RESPONSE string: " + str1);
        }
        while ((str1 = readLine(this.socketIn)) != null) {
            if (str1.startsWith("TRUSTED_CERTS=")) {
                localObject = str1.substring("TRUSTED_CERTS=".length());
                this.trustrootFilenames = ((String) localObject).split(",");
                this.trustrootData = new String[this.trustrootFilenames.length];
                for (int j = 0; j < this.trustrootFilenames.length; j++) {
                    String str2 = "FILEDATA_" + this.trustrootFilenames[j]
                            + "=";
                    str1 = readLine(this.socketIn);
                    if (str1 == null) {
                        throw new EOFException();
                    }
                    if (!str1.startsWith(str2)) {
                        throw new ProtocolException(
                                "bad MyProxy protocol RESPONSE: expecting "
                                        + str2 + " but received " + str1);
                    }

                    if (str1.length() > str2.length()) {
                        this.trustrootData[j] = new String(Base64.decode(str1
                                .substring(str2.length())));
                    }// TODO add warning
                }
            }
        }
        this.state = State.LOGGEDON;
    }

    /**
     * Retrieves credentials from the MyProxy server.
     */
    public void getCredentials() throws IOException, GeneralSecurityException {
        if (this.state != State.LOGGEDON) {
            logon();
        }
        KeyPairGenerator localKeyPairGenerator = KeyPairGenerator
                .getInstance("RSA");
        localKeyPairGenerator.initialize(1024);
        this.keypair = localKeyPairGenerator.genKeyPair();
        PKCS10CertificationRequest localPKCS10CertificationRequest = new PKCS10CertificationRequest(
                "SHA1withRSA", new X500Principal("CN=ignore"),
                this.keypair.getPublic(), null, this.keypair.getPrivate(),
                "SunRsaSign");
        this.socketOut.write(localPKCS10CertificationRequest.getEncoded());
        this.socketOut.flush();
        int i = this.socketIn.read();
        if (i == -1) {
            System.err.println("connection aborted");
            System.exit(1);
        } else if ((i == 0) || (i < 0)) {
            System.err.print("bad number of certificates sent by server: ");
            System.err.println(Integer.toString(i));
            System.exit(1);
        }
        CertificateFactory localCertificateFactory = CertificateFactory
                .getInstance("X.509");
        this.certificateChain = localCertificateFactory
                .generateCertificates(this.socketIn);
        this.state = State.DONE;
    }

    /**
     * Writes the retrieved credentials to the Globus proxy file location.
     */
    public void writeProxyFile() throws IOException, GeneralSecurityException {
        saveCredentialsToFile(getProxyLocation());
    }

    /**
     * Writes the retrieved credentials to the specified output stream.
     *
     * @param os
     *            OutputStream to write to
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void saveCredentials(OutputStream paramOutputStream)
            throws IOException, GeneralSecurityException {
        Iterator localIterator = this.certificateChain.iterator();
        X509Certificate localX509Certificate = (X509Certificate) localIterator
                .next();
        PrintStream localPrintStream = new PrintStream(paramOutputStream);
        printCert(localX509Certificate, localPrintStream);
        printKey(this.keypair.getPrivate(), localPrintStream);
        while (localIterator.hasNext()) {
            localX509Certificate = (X509Certificate) localIterator.next();
            printCert(localX509Certificate, localPrintStream);
        }
    }

    /**
     * Writes the retrieved credentials to the specified filename.
     */
    public void saveCredentialsToFile(String paramString) throws IOException,
            GeneralSecurityException {
        File localFile = new File(paramString);
        localFile.delete();
        localFile.createNewFile();
        setFilePermissions(paramString, "0600");
        FileOutputStream localFileOutputStream = new FileOutputStream(localFile);
        saveCredentials(localFileOutputStream);
        localFileOutputStream.flush();
        localFileOutputStream.close();
    }

    /**
     * Writes the retrieved trust roots to the Globus trusted certificates
     * directory.
     *
     * @return true if trust roots are written successfully, false if no
     *         trust roots are available to be written
     */
    public boolean writeTrustRoots() throws IOException {
        return writeTrustRoots(getTrustRootPath());
    }

    /**
     * Writes the retrieved trust roots to a trusted certificates directory.
     *
     * @param paramString
     *            path where the trust roots should be written
     * @return true if trust roots are written successfully, false if no
     *         trust roots are available to be written
     */
    public boolean writeTrustRoots(String paramString) throws IOException {
        if ((this.trustrootFilenames == null) || (this.trustrootData == null)) {
            return false;
        }
        File localFile = new File(paramString);
        if (!localFile.exists()) {
            localFile.mkdirs();
        }
        for (int i = 0; i < this.trustrootFilenames.length; i++) {
            FileOutputStream localFileOutputStream = new FileOutputStream(
                    paramString + File.separator + this.trustrootFilenames[i]);
            if (this.trustrootData[i] != null) {
                localFileOutputStream.write(this.trustrootData[i].getBytes());
            }
            localFileOutputStream.close();
        }
        return true;
    }

    /**
     * Gets the trusted CA certificates returned by the MyProxy server.
     *
     * @return trusted CA certificates, or null if none available
     */
    public X509Certificate[] getTrustedCAs() throws CertificateException {
        if (this.trustrootData == null) {
            return null;
        }
        return getX509CertsFromStringList(this.trustrootData,
                this.trustrootFilenames);
    }

    private static X509Certificate[] getX509CertsFromStringList(
            String[] paramArrayOfString1, String[] paramArrayOfString2)
            throws CertificateException {
        CertificateFactory localCertificateFactory = CertificateFactory
                .getInstance("X.509");
        ArrayList localArrayList = new ArrayList(paramArrayOfString1.length);
        for (int i = 0; i < paramArrayOfString1.length; i++) {
            int j = -1;
            String str = paramArrayOfString1[i];
            if (str != null) {
                j = str.indexOf("-----BEGIN CERTIFICATE-----");
            }
            if (j >= 0) {
                str = str.substring(j);
                ByteArrayInputStream localByteArrayInputStream = new ByteArrayInputStream(
                        str.getBytes());
                try {
                    X509Certificate localX509Certificate = (X509Certificate) localCertificateFactory
                            .generateCertificate(localByteArrayInputStream);
                    localArrayList.add(localX509Certificate);
                } catch (Exception localException) {
                    if (paramArrayOfString2 != null) {
                        logger.warning(paramArrayOfString2[i]
                                + " can not be parsed as an X509Certificate.");
                    } else {
                        logger.warning("failed to parse an X509Certificate");
                    }
                }
            }
        }
        if (localArrayList.isEmpty()) {
            return null;
        }
        return (X509Certificate[]) localArrayList
                .toArray(new X509Certificate[0]);
    }

    /**
     * Gets the CRLs returned by the MyProxy server.
     *
     * @return CRLs or null if none available
     */
    public X509CRL[] getCRLs() throws CertificateException {
        if (this.trustrootData == null) {
            return null;
        }
        CertificateFactory localCertificateFactory = CertificateFactory
                .getInstance("X.509");
        ArrayList localArrayList = new ArrayList(this.trustrootData.length);
        for (int i = 0; i < this.trustrootData.length; i++) {
            String str = this.trustrootData[i];
            int j = str.indexOf("-----BEGIN X509 CRL-----");
            if (j >= 0) {
                str = str.substring(j);
                ByteArrayInputStream localByteArrayInputStream = new ByteArrayInputStream(
                        str.getBytes());
                try {
                    X509CRL localX509CRL = (X509CRL) localCertificateFactory
                            .generateCRL(localByteArrayInputStream);
                    localArrayList.add(localX509CRL);
                } catch (Exception localException) {
                    logger.warning(this.trustrootFilenames[i]
                            + " can not be parsed as an X509CRL.");
                }
            }
        }
        if (localArrayList.isEmpty()) {
            return null;
        }
        return (X509CRL[]) localArrayList.toArray(new X509CRL[0]);
    }

    /**
     * Returns the trusted certificates directory location where
     * writeTrustRoots() will store certificates.
     */
    public static String getTrustRootPath() {
        String str = System.getenv("X509_CERT_DIR");
        if (str == null) {
            str = System.getProperty("X509_CERT_DIR");
        }
        if (str == null) {
            str = System.getProperty("user.home") + "/.globus/certificates";
        }
        return str;
    }

    /**
     * Gets the existing trusted CA certificates directory.
     *
     * @return directory path string or null if none found
     */
    public static String getExistingTrustRootPath() {
        String str2 = System.getenv("GLOBUS_LOCATION");
        if (str2 == null) {
            str2 = System.getProperty("GLOBUS_LOCATION");
        }
        String str1 = System.getenv("X509_CERT_DIR");
        if (str1 == null) {
            str1 = System.getProperty("X509_CERT_DIR");
        }
        if (str1 == null) {
            str1 = getDir(System.getProperty("user.home")
                    + "/.globus/certificates");
        }
        if (str1 == null) {
            str1 = getDir("/etc/grid-security/certificates");
        }
        if (str1 == null) {
            str1 = getDir(str2 + File.separator + "share" + File.separator
                    + "certificates");
        }
        return str1;
    }

    /**
     * Returns the default Globus proxy file location.
     */
    public static String getProxyLocation() throws IOException {
        String str2 = null;
        String str1 = System.getenv("X509_USER_PROXY");
        if (str1 == null) {
            str1 = System.getProperty("X509_USER_PROXY");
        }
        if (str1 != null) {
            return str1;
        }
        try {
            Process localProcess = Runtime.getRuntime().exec("id -u");
            BufferedReader localBufferedReader = new BufferedReader(
                    new InputStreamReader(localProcess.getInputStream()));
            str2 = localBufferedReader.readLine();
        } catch (IOException localIOException) {
        }
        if (str2 == null) {
            str2 = System.getProperty("user.name");
            if (str2 != null) {
                str2 = str2.toLowerCase();
            } else {
                str2 = "nousername";
            }
        }
        if (File.separator.equals("/")) {
            return "/tmp/x509up_u" + str2;
        }
        return System.getProperty("java.io.tmpdir") + File.separator
                + "x509up_u" + str2;
    }

    /**
     * Provides a simple command-line interface.
     */
    public static void main(String[] paramArrayOfString) {
        try {
            MyProxyLogon localMyProxyLogon = new MyProxyLogon();
            String str = null;
            logger.setLevel(Level.ALL);
            System.out
                    .println("Warning: terminal will echo passphrase as you type.");
            System.out.print("MyProxy Passphrase: ");
            str = readLine(System.in);
            if (str == null) {
                System.err.println("Error reading passphrase.");
                System.exit(1);
            }
            localMyProxyLogon.setPassphrase(str);
            localMyProxyLogon.requestTrustRoots(true);
            localMyProxyLogon.getCredentials();
            localMyProxyLogon.writeProxyFile();
            System.out.println("Credential written successfully.");
            X509Certificate[] arrayOfX509Certificate = localMyProxyLogon
                    .getTrustedCAs();
            if (arrayOfX509Certificate != null) {
                System.out.println(Integer
                        .toString(arrayOfX509Certificate.length)
                        + " CA certificates received.");
            }
            X509CRL[] arrayOfX509CRL = localMyProxyLogon.getCRLs();
            if (arrayOfX509CRL != null) {
                System.out.println(Integer.toString(arrayOfX509CRL.length)
                        + " CRLs received.");
            }
            if (localMyProxyLogon.writeTrustRoots()) {
                System.out.println("Wrote trust roots to " + getTrustRootPath()
                        + ".");
            } else {
                System.out
                        .println("Received no trust roots from MyProxy server.");
            }
        } catch (Exception localException) {
            localException.printStackTrace(System.err);
        }
    }

    private static void printB64(byte[] paramArrayOfByte,
            PrintStream paramPrintStream) {
        byte[] arrayOfByte = Base64.encode(paramArrayOfByte);
        for (int i = 0; i < arrayOfByte.length; i += 64) {
            if (arrayOfByte.length - i > 64) {
                paramPrintStream.write(arrayOfByte, i, 64);
            } else {
                paramPrintStream.write(arrayOfByte, i, arrayOfByte.length - i);
            }
            paramPrintStream.println();
        }
    }

    private static void printCert(X509Certificate paramX509Certificate,
            PrintStream paramPrintStream) throws CertificateEncodingException {
        paramPrintStream.println("-----BEGIN CERTIFICATE-----");
        printB64(paramX509Certificate.getEncoded(), paramPrintStream);
        paramPrintStream.println("-----END CERTIFICATE-----");
    }

    private static void printKey(PrivateKey paramPrivateKey,
            PrintStream paramPrintStream) throws IOException {
        paramPrintStream.println("-----BEGIN RSA PRIVATE KEY-----");
        ByteArrayInputStream localByteArrayInputStream = new ByteArrayInputStream(
                paramPrivateKey.getEncoded());
        ASN1InputStream localASN1InputStream = new ASN1InputStream(
                localByteArrayInputStream);
        DERObject localDERObject1 = localASN1InputStream.readObject();
        PrivateKeyInfo localPrivateKeyInfo = new PrivateKeyInfo(
                (ASN1Sequence) localDERObject1);
        DERObject localDERObject2 = localPrivateKeyInfo.getPrivateKey();
        ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
        DEROutputStream localDEROutputStream = new DEROutputStream(
                localByteArrayOutputStream);
        localDEROutputStream.writeObject(localDERObject2);
        printB64(localByteArrayOutputStream.toByteArray(), paramPrintStream);
        paramPrintStream.println("-----END RSA PRIVATE KEY-----");
        localASN1InputStream.close();
        localDEROutputStream.close();
    }

    private static void setFilePermissions(String paramString1,
            String paramString2) {
        String str = "chmod " + paramString2 + " " + paramString1;
        try {
            Runtime.getRuntime().exec(str);
        } catch (IOException localIOException) {
            logger.warning("Failed to run: " + str);
        }
    }

    private static String readLine(InputStream paramInputStream)
            throws IOException {
        StringBuffer localStringBuffer = new StringBuffer();
        for (int i = paramInputStream.read(); (i > 0) && (i != 10); i = paramInputStream
                .read()) {
            localStringBuffer.append((char) i);
        }
        if (localStringBuffer.length() > 0) {
            return new String(localStringBuffer);
        }
        return null;
    }

    private static String getDir(String paramString) {
        if (paramString == null) {
            return null;
        }
        File localFile = new File(paramString);
        if ((localFile.isDirectory()) && (localFile.canRead())) {
            return localFile.getAbsolutePath();
        }
        return null;
    }

    private class MyTrustManager implements X509TrustManager {
        private MyTrustManager() {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {

            if (bootstrap) { // if bootstrap accept all issuers
                return null;
            }

            X509Certificate[] arrayOfX509Certificate = null;
            String str = MyProxyLogon.getExistingTrustRootPath();
            if (str == null) {
                return null;
            }
            File localFile = new File(str);
            if (!localFile.isDirectory()) {
                return null;
            }
            String[] arrayOfString1 = localFile.list();
            String[] arrayOfString2 = new String[arrayOfString1.length];
            for (int i = 0; i < arrayOfString1.length; i++) {
                try {
                    FileInputStream localFileInputStream = new FileInputStream(
                            str + File.separator + arrayOfString1[i]);
                    byte[] arrayOfByte = new byte[localFileInputStream
                            .available()];
                    localFileInputStream.read(arrayOfByte);
                    arrayOfString2[i] = new String(arrayOfByte);
                    localFileInputStream.close();
                } catch (Exception localException2) {
                }
            }
            try {
                arrayOfX509Certificate = MyProxyLogon
                        .getX509CertsFromStringList(arrayOfString2,
                                arrayOfString1);
            } catch (Exception localException1) {
            }
            return arrayOfX509Certificate;
        }

        @Override
        public void checkClientTrusted(
                X509Certificate[] paramArrayOfX509Certificate,
                String paramString) throws CertificateException {
            throw new CertificateException(
                    "checkClientTrusted not implemented by edu.uiuc.ncsa.MyProxy.MyProxyLogon.MyTrustManager");
        }

        @Override
        public void checkServerTrusted(
                X509Certificate[] paramArrayOfX509Certificate,
                String paramString) throws CertificateException {
            checkServerCertPath(paramArrayOfX509Certificate);
            checkServerDN(paramArrayOfX509Certificate[0]);
        }

        private void checkServerCertPath(
                X509Certificate[] paramArrayOfX509Certificate)
                throws CertificateException {
            try {
                CertPathValidator localCertPathValidator = CertPathValidator
                        .getInstance(CertPathValidator.getDefaultType());
                CertificateFactory localCertificateFactory = CertificateFactory
                        .getInstance("X.509");
                CertPath localCertPath = localCertificateFactory
                        .generateCertPath(Arrays
                                .asList(paramArrayOfX509Certificate));
                X509Certificate[] arrayOfX509Certificate = getAcceptedIssuers();
                // if getAcceptedIssuers == null then bootstrap server
                if (arrayOfX509Certificate == null) {

                    if (!bootstrap) { // only do this check if bootstarp option
                                      // isn't active
                        String localObject = MyProxyLogon
                                .getExistingTrustRootPath();
                        if (localObject != null) {
                            throw new CertificateException(
                                    "no CA certificates found in "
                                            + localObject);
                        }
                        if (!MyProxyLogon.this.requestTrustRoots) {
                            throw new CertificateException(
                                    "no CA certificates directory found");
                        }
                    }

                    MyProxyLogon.logger
                            .info("no trusted CAs configured -- bootstrapping trust from MyProxy server");
                    arrayOfX509Certificate = new X509Certificate[1];
                    arrayOfX509Certificate[0] = paramArrayOfX509Certificate[(paramArrayOfX509Certificate.length - 1)];
                }
                Object localObject = new HashSet(arrayOfX509Certificate.length);
                for (int i = 0; i < arrayOfX509Certificate.length; i++) {
                    TrustAnchor localTrustAnchor = new TrustAnchor(
                            arrayOfX509Certificate[i], null);
                    ((Set) localObject).add(localTrustAnchor);
                }
                PKIXParameters localPKIXParameters = new PKIXParameters(
                        (Set) localObject);
                localPKIXParameters.setRevocationEnabled(false);
                localCertPathValidator.validate(localCertPath,
                        localPKIXParameters);
            } catch (CertificateException localCertificateException) {
                throw localCertificateException;
            } catch (GeneralSecurityException localGeneralSecurityException) {
                throw new CertificateException(localGeneralSecurityException);
            }
        }

        private void checkServerDN(X509Certificate paramX509Certificate)
                throws CertificateException {
            String str1 = paramX509Certificate.getSubjectX500Principal()
                    .getName();
            MyProxyLogon.logger.fine("MyProxy server DN: " + str1);
            int i = str1.indexOf("CN=");
            if (i == -1) {
                throw new CertificateException("Server certificate subject ("
                        + str1 + "does not contain a CN component.");
            }
            String str2 = str1.substring(i + 3);
            i = str2.indexOf(',');
            if (i >= 0) {
                str2 = str2.substring(0, i);
            }
            if ((i = str2.indexOf('/')) >= 0) {
                String str3 = str2.substring(0, i);
                str2 = str2.substring(i + 1);
                if ((!str3.equals("host")) && (!str3.equals("myproxy"))) {
                    throw new CertificateException(
                            "Server certificate subject CN contains unknown service element: "
                                    + str1);
                }
            }
            String str3 = MyProxyLogon.this.host;
            if (str3.equals("localhost")) {
                try {
                    str3 = InetAddress.getLocalHost().getHostName();
                } catch (Exception localException) {
                }
            }
            if (!str2.equals(str3)) {
                throw new CertificateException(
                        "Server certificate subject CN (" + str2
                                + ") does not match server hostname ("
                                + MyProxyLogon.this.host + ").");
            }
        }
    }

    protected static enum State {
        READY, CONNECTED, LOGGEDON, DONE;

        private State() {
        }
    }

    /**
     * Configure MyProxy request to do bootstrap
     * 
     * @param bootstrap
     */
    public void setBootstrap(boolean bootstrap) {
        this.bootstrap = bootstrap;
    }
}
