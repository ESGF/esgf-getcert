package esg.security.myproxy;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * This tests are not prepared for the general use case and require a proper
 * OpenID account
 * 
 * @author egonzalez
 * 
 */
public class MyProxyConsoleTest {
	private static String TMP_DIR;
	private static String TMP_CERTS;
	private static String TMP_CREADENTIAL;
	private static String PORT;
	private static String SERVER;
	private static String OID;
	private static String PASS;

	@BeforeClass
	public static void prepare() throws Exception {
		File f = File.createTempFile("MzProxyConsoleTests", null);
		f.delete();
		f.mkdir();

		TMP_DIR = f.getAbsolutePath();
		TMP_CERTS = TMP_DIR + File.separator + "certs";
		TMP_CREADENTIAL = TMP_DIR + File.separator + "credential.pem";
		PORT = "2119";
		SERVER = "pcmdi3.llnl.gov";
		OID = "https://pcmdi3.llnl.gov/esgcet/myopenid/estani";
		System.out.print("Password? ");
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		try {
			// if passed directly I got problems at my linux terminal, not
			// sure why
			PASS = in.readLine();
		} catch (IOException e) {
			System.err.println("Error accessing Stdin: " + e.getMessage());
			System.exit(100);
		}
		System.out.println("");
	}

	public void testShowUsage() throws Exception {
		MyProxyConsole.main("--help".split(" "));
	}

	@Test
	public void testEnvironment() throws Exception {
		System.setProperty("MYPROXY_SERVER", SERVER);
		System.setProperty("MYPROXY_SERVER_PORT", PORT);
		System.setProperty("X509_CERT_DIR", TMP_CERTS);
		System.setProperty("X509_USER_PROXY", TMP_CREADENTIAL);

		MyProxyConsole.main(String.format("-P %s", PASS).split(" "));
	}

	@Test
	public void testOpenId() throws Exception {
		System.setProperty("X509_CERT_DIR", TMP_CERTS);
		System.setProperty("X509_USER_PROXY", TMP_CREADENTIAL);

		MyProxyConsole.main(String.format("--oid %s -P %s", OID, PASS).split(
				" "));
	}
}
