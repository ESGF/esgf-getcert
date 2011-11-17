/**
 * 
 */
package esg.security.myproxy;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.MalformedURLException;

import org.junit.Test;

/**
 * @author Estani
 *
 */
public class GSSICertificateConnectionTest {

    /**
     * Test method for {@link org.globus.esg.myproxy.GSSICredentialConnection#setupFromOpenID(java.lang.String)}.
     */
    @Test
    public void testSetupFromOpenID() {
        GSSICredentialConnection conn = new GSSICredentialConnection(true);
        try {
            conn.setupFromOpenID("hasdfttps://asldhlakjhs");
            fail("Malformed URL!");
        } catch (MalformedURLException e) {
            //ok
        } catch (IOException e) {
            e.printStackTrace();
            fail("Unexpected Exception.");
        }
        
        try {
            conn.setupFromOpenID("https://albedo2.dkrz.de/myopenid/_$_$_$_$_$_$_$");
            fail("Unexistent user!!");
        } catch (MalformedURLException e) {
            e.printStackTrace();
            fail("Unexpected Exception.");
        } catch (IOException e) {
            //ok
        }
        
        try {
            conn.setupFromOpenID("https://ipcc-ar5.dkrz.de/myopenid/dkrzpub1");
            //ok
        } catch (MalformedURLException e) {
            e.printStackTrace();
            fail("Unexpected Exception.");
        } catch (IOException e) {
            e.printStackTrace();
            fail("Unexpected Exception.");
        }
    }

    /**
     * Test method for {@link org.globus.esg.myproxy.GSSICredentialConnection#getCredential()}.
     * @throws Exception not expected 
     */
    public void testGetCertificate() throws Exception {
        System.setProperty("X509_CERT_DIR", "E:/certs/esg-certs");
        System.setProperty("X509_USER_PROXY", "E:/certs/certificate.pem");
        
        GSSICredentialConnection conn = new GSSICredentialConnection(true);
        conn.setupFromOpenID("https://ipcc-ar5.dkrz.de/myopenid/dkrzpub1");
        conn.setPassword("");
        conn.writeCertificate("E:/certs/certificate.pem");
        
    }

    /**
     * Test method for {@link org.globus.esg.myproxy.GSSICredentialConnection#writeTrustRoots(java.lang.String)}.
     * @throws Exception not expected 
     */
    public void testWriteTrustRoots() throws Exception {
        System.setProperty("X509_CERT_DIR", "E:/certs/esg-certs");
        System.setProperty("X509_USER_PROXY", "E:/certs/certificate.pem");
        
        GSSICredentialConnection conn = new GSSICredentialConnection(true);
        conn.setHost("ipcc-ar5.dkrz.de");
        conn.setPort(7512);
        conn.setUsername("dkrzpub1");
        conn.setPassword("");
        conn.setTrustRoots(true);
        conn.setBootStrap(true);
        
        
        conn.writeTrustRoots(null);
    }

}
