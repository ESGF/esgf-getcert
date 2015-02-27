package esg.security.myproxy;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;

import edu.uiuc.ncsa.MyProxy.MyProxyLogon;



/**
 * Wraps the Wraps the edu.uiuc.ncsa.myproxy.MyProxyLogon. Everything here is cached, 
 * so it is intended to be used only once.
 * @author  Estani
 * @author  Karem Terry
 */
public class CredentialConnection {
	
	/** Logger. */
	private static Log LOG = LogFactory.getLog(CredentialConnection.class);
	/** Singleton instance. */
    private static CredentialConnection INSTANCE = null;
    /** Pointer to the myproxy URI in the openID XRDS file. */
    private static final String XPATH      = "//*[Type='urn:esg:security:myproxy-service']/URI";
    
	private boolean bootStrap = false;
	private boolean trustRoots = false;
	private String username;
	private String password;
	private String host;
	private int port = 0;
	private String caDirectory;
    private MyProxyLogon myProxyLogon;
	private String openId;
	//defaults to maximum allowed in the CMIP5 federation
	private int lifetime = 72 * 60 * 60;
    private boolean debug = false;
	private Collection<X509Certificate> x509Certificates;
	private PrivateKey privateKey;
    
    /**
     * Get singleton instance of {@link CredentialConnection}. This instance is
     * the only that exists.
     * 
     * @return the unique instance of {@link CredentialConnection}.
     */
    public static CredentialConnection getInstance() {
        createInstance();
        return INSTANCE;
    }
    
    /**
     * Create a thread-safe singleton.
     */
    private static void createInstance() {

        LOG.debug("Checking if exist an instance of CredentialConnection");
        // creating a thread-safe singleton
        if (INSTANCE == null) {

            // Only the synchronized block is accessed when the instance hasn't
            // been created.
            synchronized (CredentialConnection.class) {
                // Inside the block it must check again that the instance has
                // not been created.
                if (INSTANCE == null) {
                    LOG.debug("Creating new instance of CredentialConnection");
                    INSTANCE = new CredentialConnection();
                }
            }
        }
    }

    /**
     * Constructor.
     */
    private CredentialConnection() {
	}
    
    /**
     * Shows an xml for debugging purposes
     * @param doc xml document
     * @param out where to write to
     * @throws Exception if somehting goes wrong
     */
    private static void serialize(Document doc, OutputStream out)
            throws Exception {
        TransformerFactory tfactory = TransformerFactory.newInstance();
        Transformer serializer;
        try {
            serializer = tfactory.newTransformer();
            // Setup indenting to "pretty print"
            serializer.setOutputProperty(OutputKeys.INDENT, "yes");
            serializer.setOutputProperty(
                    "{http://xml.apache.org/xslt}indent-amount", "2");

            serializer.transform(new DOMSource(doc), new StreamResult(out));
        } catch (TransformerException e) {
            // this is fatal, just dump the stack and throw a runtime exception
            e.printStackTrace();

            throw new RuntimeException(e);
        }
    }
    
	public boolean getDebug() {
		return this.debug;
	}
	
	public void setDebug(boolean debug){
		this.debug = debug;
	}
    
    public String getUsername() {
        return username;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }
	public String getCADir() {
		return caDirectory;
	}
	private String getOpenId() {
		return openId;
	}
	
	private int getLifetime() {
		return this.lifetime;
	}
	/**
	 * @param time in hours
	 */
	public void setLifetime(int time) {
		//we issue seconds though
		this.lifetime = time * 60 * 60;
		
	}

	public void setCADir(String value) {
		caDirectory = value;
	}

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setBootStrap(boolean bootStrap) {
        this.bootStrap = bootStrap;
    }

    public void setTrustRoots(boolean trustRoots) {
        this.trustRoots = trustRoots;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String setupFromOpenID(String oid) throws MalformedURLException,
    IOException {
    	setOpenID(oid);
    	setUsername(oid.substring(oid.lastIndexOf("/") + 1));
    	// try to parse the url (MalformedURLException)
    	URL url = new URL(oid);

    	// try to get the page (IOException if it fails
    	InputStream in=null;
    	try{
    		URLConnection conn = url.openConnection();
    		in = conn.getInputStream();
    	}catch (SSLHandshakeException e){

    		LOG.warn("SSLHandshakeException, removing SSLv3 and SSLv2Hello protocols");
    		try {

    			SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    			SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(url.getHost(), 443);

    			// Strip "SSLv3" from the current enabled protocols.
    			String[] protocols = sslSocket.getEnabledProtocols();
    			Set<String> set = new HashSet<String>();
    			for (String s : protocols) {
    				if (s.equals("SSLv3") || s.equals("SSLv2Hello")) {
    					continue;
    				}
    				set.add(s);
    			}
    			sslSocket.setEnabledProtocols(set.toArray(new String[0]));

    			//get openID xml
    			PrintWriter out = new PrintWriter(
    					new OutputStreamWriter(
    							sslSocket.getOutputStream()));
    			out.println("GET " + url.toString() + " HTTP/1.1");
    			out.println();
    			out.flush();

    			//read openid url content
    			in = sslSocket.getInputStream();
    			final BufferedReader reader = new BufferedReader(
    					new InputStreamReader(in));

    			//read headers
    			boolean head=true;
    			int headLen = 0;
    			int contentLen=0;
    			String line = null;
    			line = reader.readLine();

    			while (head==true & line!=null) {
    				if(head){
    					headLen = headLen+line.length();
    					if(line.trim().equals("")){
    						head=false;
    					}else{
    						String[] headers = line.trim().split(" ");
    						if(headers[0].equals("Content-Length:")){
    							contentLen = Integer.parseInt(headers[1]);
    						}
    						line = reader.readLine();
    					}
    				}
    			}

    			//read content
    			char[] buffContent = new char[contentLen];
    			reader.read(buffContent);
    			reader.close();

    			//make inpuStream for the content
    			String content = new String(buffContent);
    			in = new ByteArrayInputStream(content.getBytes());


    		} catch (Exception e1) {
    			System.err.println("Can't parse OpenID: " + e.getMessage());
    		}

    	}

    	try {
    		// now get the info we need
    		Document doc = DocumentBuilderFactory.newInstance()
    				.newDocumentBuilder().parse(in);
    		try {
    			if (debug) serialize(doc, System.out);
    		} catch (Exception e) {
    			e.printStackTrace();
    		}

    		XPath xpath = XPathFactory.newInstance().newXPath();
    		XPathExpression xpSocket = xpath.compile(XPATH);

    		String myProxyServer = (String) xpSocket.evaluate(doc,
    				XPathConstants.STRING);
    		String[] results = myProxyServer.split(":");

    		setHost(results[1].substring(2));
    		setPort(Integer.parseInt(results[2]));

    		return myProxyServer;
    	} catch (Exception e) {
    		// this file is unparsable log and done
    		System.err.println("Coan't parse OpenID: " + e.getMessage());
    	}

    	// try to close the stream. Don't fail on this though.
    	try {
    		in.close();
    	} catch (IOException e) {
    	}

    	return null;
    }
    
    private void setOpenID(String oid) {
		openId = oid;
	}

    /**
     * Configure {@link MyProxyLogon}
     */
	private MyProxyLogon getConnection() {
		if (this.myProxyLogon == null) {
			this.myProxyLogon = new MyProxyLogon();
			this.myProxyLogon.setUsername(this.username);
			this.myProxyLogon.setPassphrase(this.password);
			this.myProxyLogon.setHost(this.host);
			this.myProxyLogon.setPort(this.port);
			this.myProxyLogon.setLifetime(this.lifetime);
			this.myProxyLogon.requestTrustRoots(this.trustRoots);
			LOG.debug("MyProxyLogon generated: + host" + this.host
					+ " username:" + this.username + "pass: " + this.password
					+ " port:" + this.port + "lifetime: " + this.lifetime
					+ "trustRoots:" + this.trustRoots);
		}

		return this.myProxyLogon;
	}

	/**
     * Retrieve credentials from the MyProxy server and writes the retrieved trust 
     * roots to certificates directory if trustRoots are required setTrustRoots(true).
     * 
     * @throws IOException
     * @throws GeneralSecurityException
     */
	public void getCredential() throws IOException, GeneralSecurityException {
		LOG.debug("Generating MyProxyLogon object..");
		MyProxyLogon myProxyLogon = getConnection();

		LOG.debug("Retrieving credentials from the MyProxy server..");
		myProxyLogon.getCredentials();
		LOG.debug("done!");

		if (this.trustRoots) {
			try {
				LOG.info("Writing trust roots to " + this.caDirectory);
				myProxyLogon.writeTrustRoots(this.caDirectory);
				LOG.debug("Retrieved trust roots writed in " + this.caDirectory);
			} catch (IOException e) {
				LOG.error("Couldn't write certificates");
				System.exit(1);
			}
		}

		this.x509Certificates = this.myProxyLogon.getCertificates();
		LOG.debug("X509Certificates:\n "
				+ this.x509Certificates);
		
		this.privateKey = myProxyLogon.getPrivateKey();
		LOG.debug("PrivateKey:" + this.privateKey.toString());
	}
    
	/**
     * @param path to where the certificate will be saved.
     * @throws GeneralSecurityException If parameters are not properly set.
     * @throws IOException if retrieval/storage fails
     */
	public void writeCertificate(String path) throws IOException,
	GeneralSecurityException {
		File file = new File(path);
		file.createNewFile();

		file.setReadable(true, true);
		file.setWritable(true, true);

		OutputStream out = null;
		out = new FileOutputStream(path);

		writeCertificate(out);
	}
    
	 /**
     * @return the String representation of this certificate
     * @throws GeneralSecurityException If parameters are not properly set.
     * @throws IOException if retrieval/storage fails
     */
	public String getCertificateAsString() throws IOException,
	GeneralSecurityException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		writeCertificate(out);

		return out.toString();
	}
    
	/**
	 * Write certificate in .pem format into output stream
	 * @param out output stream of bytes
     * @throws GeneralSecurityException If parameters are not properly set.
     * @throws IOException if retrieval/storage fails
     */
    private void writeCertificate(OutputStream out) throws IOException,
    GeneralSecurityException {
    	LOG.debug("Retrieving credentials from the MyProxy server...");
    	getCredential();

    	LOG.debug("Writing credentials in pem format...");
    	PemUtil.writeCredentials(out, this.x509Certificates, this.privateKey);	
    }
    
    /**
     * Uses default location (X509_DERT_DIR) for storing trustroots.
     */
    public boolean writeTrustRoots() throws GeneralSecurityException, IOException {
		return writeTrustRoots(null);
	}
    
    /**
     * @param directory to where the trustroots will be stored
     * @return if the operation was successful
     * @throws IOException if the connection fails
     * @throws GeneralSecurityException if something is not properly setup
     */
    public boolean writeTrustRoots(String directory) throws GeneralSecurityException, IOException {
		String oldValue = System.getProperty("X509_CERT_DIR");
		// use default if empty
		if (directory == null) {
			directory = oldValue;
		}
		// this is a workaround, directory must not exists.
		if (this.bootStrap) {
			System.setProperty("X509_CERT_DIR", directory);
			File dir = new File(directory);
			if (dir.exists()) {
				List remaining = new LinkedList(Arrays.asList(dir.listFiles()));
				while (!(remaining.isEmpty())) {
					File f = (File) remaining.remove(0);
					if (f.isDirectory())
						remaining.addAll(Arrays.asList(f.listFiles()));
					else
						f.delete();
				}
				if (!(dir.delete())) {
					throw new GeneralSecurityException(
							"Could not clean directory:" + directory);
				}

			}

		}
		// know we need to get the certificate to be able to get the list of all
        // certs.
		getCredential();
		// restore the property
		System.setProperty("X509_CERT_DIR", oldValue);
		// gather all CA certs
		return this.myProxyLogon.writeTrustRoots(directory);
	}

    @Override
    public String toString() {
        String pass;
        if (password != null && password.length() > 0) pass = password
                .replaceAll(".", "*");
        else pass = "[none]";

        return String.format("%s:%s@%s:%d", username, pass, host, port);
    }
    
	
    protected static final String usernameProperty = "Username";
    protected static final String hostnameProperty = "Hostname";
    protected static final String portProperty = "Port";
    protected static final String openidProperty = "OpenID";

    public void saveProperties(File filename) {
        try {
            FileOutputStream out = new FileOutputStream(filename);
            
        	Properties prop = new Properties();
        	prop.setProperty(usernameProperty, getUsername());
        	prop.setProperty(hostnameProperty, getHost());
        	prop.setProperty(portProperty, Integer.toString(getPort()));
        	prop.setProperty(openidProperty, getOpenId());
        	prop.store(out, "Created by MyProxyConsole");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
	public void loadProperties(File filename) {
		try {
			Properties prop = new Properties();
			FileInputStream in = new FileInputStream(
					filename);
			prop.load(in);
			setUsername(prop.getProperty(usernameProperty));
			setHost(prop.getProperty(hostnameProperty));
			setOpenID(prop.getProperty(openidProperty));
			
			String port = prop.getProperty(portProperty);
			if (port != null) 
				setPort(Integer.parseInt(port));
		} catch (FileNotFoundException e) {
			// ok, nothing to load
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
}
