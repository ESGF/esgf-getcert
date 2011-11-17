package esg.security.myproxy;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
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

import org.globus.myproxy.GetParams;
import org.globus.myproxy.MyProxy;
import org.globus.myproxy.MyProxyException;
import org.globus.util.Util;
import org.gridforum.jgss.ExtendedGSSCredential;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.w3c.dom.Document;

/**
 * @author Estani
 * wraps the globus myProxy. Everything here is cached, so it is intended to
 * be used only once. It might be desired afterward, to set the constructor to private
 * and generate a getInstance method for retrieving unmodifiable instances. 
 */
public class GSSICredentialConnection {
    private static final SSLSocketFactory factory;
	private static final HostnameVerifier hostname_verifier;
    
	//craete special SSL context checker (now bootstraping it)
	static {
		SSLContext sc = null;

		// initialize Certificate checking
		try {
			// create an empty ssl context (we can change this to suit our
			// needs)
			sc = SSLContext.getInstance("SSL");
			sc.init(null, new TrustManager[] { new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}

				public void checkClientTrusted(X509Certificate[] certs,
						String authType) {
				}

				public void checkServerTrusted(X509Certificate[] certs,
						String authType) {
					System.err.println("Connecting to: "
							+ certs[0].getSubjectDN().getName());
				}
			} }, new SecureRandom());
		} catch (Exception e) {
			System.err
					.println("Can't initialize SSL factory. The current JVM is not supported.");
			e.printStackTrace();
			System.exit(-1);
		}
		factory = sc.getSocketFactory();
		hostname_verifier = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				// this gets called iff there's a certificate DN and
				// hostname mismatch
				return true;
			}

		};
	}
	
    private boolean debug = false;

    public GSSICredentialConnection(boolean debug) {
		this.debug = debug;
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

    /** Pointer to the myproxy URI in the openID XRDS file. */
    private static final String XPATH      = "//*[Type='urn:esg:security:myproxy-service']/URI";

	private boolean bootStrap = false;
	private boolean trustRoots = false;
	private String username;
	private String password;
	private String host;
	private int port = 7512;	//default
	private String caDirectory;


    private GetParams getRequest;

    private MyProxy myProxy;

    private GSSCredential credential;

	private String openId;

   

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
        
        // try to get the page (IOException if it fails)
        URLConnection conn = url.openConnection();
        if (conn instanceof HttpsURLConnection) {
        	((HttpsURLConnection)conn).setSSLSocketFactory(factory);
        	((HttpsURLConnection)conn).setHostnameVerifier(hostname_verifier);
        }
        InputStream in = conn.getInputStream();

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

	private MyProxy getConnection() throws MyProxyException {
        if (myProxy == null) {
            // setup request params
            getRequest = new GetParams();
            getRequest.setUserName(username);
            getRequest.setPassphrase(password);
            getRequest.setWantTrustroots(trustRoots);
            
            //this is the maximum we are allowing.
            getRequest.setLifetime(72 * 60 * 60);

            // setup myproxy
            myProxy = new MyProxy(host, port);

        }

        return myProxy;
    }

    /**
     * @return the GSSCredential behind the myproxy server using the parameters already set.
     * @throws MyProxyException
     */
    public GSSCredential getCredential() throws MyProxyException {
        if (credential == null) {
            // setup myproxy
            MyProxy myProxy = getConnection();

            // if the directory pointed by X509_CERT_DIR exists, this won't work
            if (bootStrap) myProxy.bootstrapTrust();

            credential = myProxy.get(null, getRequest);
            if (trustRoots)
				try {
					System.out.println("Writing trust roots to " + caDirectory);
					myProxy.writeTrustRoots(caDirectory);
				} catch (IOException e) {
					System.err.println("Couldn't write certificates");
					System.exit(1);
				}
        }

        return credential;
    }
    
    /**
     * @param path to where the certificate will be saved.
     * @throws MyProxyException If parameters are not properly set.
     * @throws IOException if retrieval/storage fails
     */
    public void writeCertificate(String path) throws MyProxyException, IOException {
        // create a file
        new File(path).createNewFile();
        
        // set read only permissions
        Util.setOwnerAccessOnly(path);
        
        OutputStream out = null;
        out = new FileOutputStream(path);
        
        writeCertificate(out);
    }
    
    /**
     * @return the String representation of this certificate
     * @throws MyProxyException If parameters are not properly set.
     * @throws IOException if retrieval/storage fails
     */
    public String getCertificateAsString()  throws MyProxyException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        writeCertificate(out);
        
        return out.toString();
    }
    
    private void writeCertificate(OutputStream out) throws MyProxyException, IOException {

         GSSCredential certificate = getCredential();
         if (certificate == null) {
             throw new MyProxyException("Certificate gathering failed for inknown reasons.");
         }
         

         try {

             // write the contents
             byte[] data =
                     ((ExtendedGSSCredential) certificate).export(ExtendedGSSCredential.IMPEXP_OPAQUE);

             out.write(data);
         } catch (GSSException e) {
            // This should never happen
            throw new MyProxyException("Could not export certificate.", e);
        } finally {
             if (out != null) {
                 try {
                     out.close();
                 } catch (Exception e) {
                 }
             }
         }
    }
    
    /**
     * Uses default location (X509_DERT_DIR) for storing trustroots.
     * <p>
     * see: {@link GSSICredentialConnection#writeTrustRoots(String)};
     */
    public boolean writeTrustRoots() throws IOException, MyProxyException {
        return writeTrustRoots(null);
    }
    
    /**
     * @param directory to where the trustroots will be stored
     * @return if the operation was successful
     * @throws IOException if the connection fails
     * @throws MyProxyException if something is not properly setup
     */
    public boolean writeTrustRoots(String directory) throws IOException,
            MyProxyException {

        String oldValue = System.getProperty("X509_CERT_DIR");
        // use default if empty
        if (directory == null) directory = oldValue;

        // this is a workaround, directory must not exists.
        if (bootStrap) {
            System.setProperty("X509_CERT_DIR", directory);
            File dir = new File(directory);
            if (dir.exists()) {
                List<File> remaining = new LinkedList<File>(Arrays.asList(dir
                        .listFiles()));
                while (!remaining.isEmpty()) {
                    File f = remaining.remove(0);
                    if (f.isDirectory()) remaining.addAll(Arrays.asList(f
                            .listFiles()));
                    else f.delete();
                }
                if (!dir.delete()) {
                    throw new MyProxyException("Could not clean directory:"
                            + directory);
                }
            }
        }
        
        // know we need to get the certificate to be able to get the list of all
        // certs.
        getCredential();

        // restore the property
        System.setProperty("X509_CERT_DIR", oldValue);

        // gather all certs
        return myProxy.writeTrustRoots(directory);
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
