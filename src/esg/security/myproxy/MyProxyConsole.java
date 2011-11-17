package esg.security.myproxy;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

import org.globus.myproxy.MyProxyException;

import esg.security.myproxy.Arguments.Argument;
import esg.security.myproxy.Arguments.InvalidArgumentException;

/**
 * Myproxy console access.
 * 
 */
public class MyProxyConsole {

	private static final String X509_USER_PROXY = "X509_USER_PROXY";
	private static final String X509_CERT_DIR = "X509_CERT_DIR";
	private static final String MYPROXY_SERVER = "MYPROXY_SERVER";
	private static final String MYPROXY_SERVER_PORT = "MYPROXY_SERVER_PORT";
	private static final String ESGF_USER_HOME = ".esg";
	private static final String X509_CERT_DIR_DEF = "certificates";
	private static final String PROPERTIES_PATH = ".MyProxyLogon";

	private static final Arguments arg = new Arguments();
	private static boolean debug = false;

	/**
	 * @param args
	 * @throws MyProxyException
	 * @throws InvalidArgumentException
	 */
	public static void main(String[] args) {

		// setup arguments
		Argument oOid = arg
				.setOption(
						"--oid",
						"OpenID endpoint from where myproxy information can be gathered.",
						true);
		Argument oUser = arg
				.setOption(
						"-l,--username",
						"Specifies the MyProxy "
								+ "account under which the credential to retrieve is stored. "
								+ "The MyProxy username "
								+ "need not correspond to a real Unix username.",
						true);
		Argument oPass = arg.setOption("-P,--password", "MyProxy password",
				true);
		// simplify for the common user, either both or none.
		// Argument oBoot = arg.setOption("-b", "Bootstrap. Don't check CAs.");
		Argument oTrust = arg.setOption("-T", "Gather server Trustroots.");
		Argument oDebug = arg.setOption("-d", "Turn debugging info on.");
		Argument oHelp = arg.setOption("-h,--help",
				"Displays command usage text and exits.");
		Argument oHost = arg
				.setOption(
						"-s,--pshost",
						"Specifies the hostname(s)"
								+ " of the myproxy-server(s). Multiple hostnames may be "
								+ "specified in a comma-separated list. This option is required "
								+ "if the MYPROXY_SERVER environment variable is not defined. If "
								+ "specified, this option overrides the MYPROXY_SERVER environment variable.",
						true, MYPROXY_SERVER);
		Argument oPort = arg.setOption("-p,--psport", "Specifies the TCP port "
				+ "number of the myproxy-server (Default: 7512).", true,
				MYPROXY_SERVER_PORT);
		Argument oCertDir = arg
				.setOption(
						"--ca-directory",
						"Directory for "
								+ "storing CAs used for connection validation. If defined this "
								+ "setting overrides the X509_CERT_DIR environment variable.",
						true, X509_CERT_DIR);
		Argument oCertFile = arg
				.setOption(
						"--output",
						"File for "
								+ "storing the retrieved myproxy certificate. If defined this "
								+ "setting overrides the X509_USER_PROXY environment variable.",
						true, X509_USER_PROXY);

		File propFile = new File(System.getProperty("user.home")
				+ File.separator + PROPERTIES_PATH);

		if (!propFile.exists() && (args == null || args.length == 0)) {
			// Fail if no property file can be found and no arguments are given.
			showUsage();
		}

		// parse them
		List<Argument> parsedArgs = null;
		try {
			parsedArgs = arg.parseArguments(args);
			if (parsedArgs.contains(oHelp))
				showUsage();
		} catch (InvalidArgumentException e1) {
			System.err.println(e1.getMessage());
			showUsage();
		}

		if (parsedArgs.contains(oDebug)) {
			debug = true;

		}

		GSSICredentialConnection conn = new GSSICredentialConnection(debug);
		// load properties if found
		conn.loadProperties(propFile);

		if (parsedArgs.contains(oCertDir)) {
			conn.setCADir(oCertDir.getValue());

		} else {
			if (System.getProperty(X509_CERT_DIR) == null
					&& System.getenv(X509_CERT_DIR) != null) {
				conn.setCADir(System.getenv(X509_CERT_DIR));
			} else {
				// just use a default one

				conn.setCADir(System.getProperty("user.home") + File.separator
						+ ESGF_USER_HOME + File.separator + X509_CERT_DIR_DEF);
			}
		}
		// we must pass this as a java property instead of an environment
		// variable
		System.setProperty(X509_CERT_DIR, conn.getCADir());

		// set the rest (overwrites oid if provided)
		if (oPort.getValue() != null) {
			try {
				conn.setPort(Integer.parseInt(oPort.getValue()));
			} catch (NumberFormatException e) {
				end("Not a valid port number: " + oPort.getValue());
			}
		}

		// use openid to find values
		if (oOid.getValue() != null) {
			String oid = oOid.getValue();
			try {
				conn.setupFromOpenID(oid);
			} catch (Exception e) {
				end("Could not parse openID " + oOid.getValue() + "\n"
						+ e.getMessage());
			}
		}

		if (oHost.getValue() != null)
			conn.setHost(oHost.getValue());
		// this is a simplification for the end user
		if (parsedArgs.contains(oTrust)) {
			/* unconditionally delete trustRootPath if it exists */
			File trustRootPath = new File(System.getProperty(X509_CERT_DIR));
			if (debug)
				System.err.println("writing trustroot to: "
						+ trustRootPath.getAbsolutePath());
			if (trustRootPath.exists()) {
				File[] credentials = trustRootPath.listFiles();
				for (int i = 0; i < credentials.length; i++) {
					credentials[i].delete();
				}
			} else {
				// Create the complete directory structure (is one too much)
				if (!trustRootPath.mkdirs()) {
					end("Can't create CA directory: "
							+ trustRootPath.getAbsolutePath());
				}
			}
			// now globus needs the directory to be removed completely
			trustRootPath.delete();
			conn.setTrustRoots(true);
			conn.setBootStrap(true);
		}
		// if (parsedArgs.contains(oBoot)) conn.setBootStrap(true);
		if (oUser.getValue() != null)
			conn.setUsername(oUser.getValue());

		// at this place we should already have all required information. Check
		// it
		if (conn.getUsername() == null)
			end("Username is missing.");
		if (conn.getHost() == null)
			end("Host server is missing.");
		if (conn.getPort() == 0)
			end("Port number is missing.");
		if (conn.getCADir() == null
				|| !new File(conn.getCADir()).getParentFile().exists())
			end("CA Directory " + conn.getCADir() + " is missing.");

		if (debug) {
			StringBuilder db = new StringBuilder();
			db.append(String.format("> Connection: %s\n", conn));
			db.append(String.format("> X509_CERT_DIR: %s\n",
					System.getProperty(X509_CERT_DIR)));
			System.err.println(db.toString());
		}

		// password provided? (if not ask)
		if (oPass.getValue() != null)
			conn.setPassword(oPass.getValue());
		else {
			System.err.printf("MyProxy Password for user %s: ",
					conn.getUsername());
			// Java 1.6 Allows to use Console which is the only way, we could
			// get user input without echoing it. (BUt this breaks 1.5 compat...
			// Console console = System.console();
			// if (console != null) {
			// char[] pass = console.readPassword();
			// if (pass == null) {
			// //this happens if you hit ctrl-C, which is probable.
			// System.exit(1);
			// }
			// conn.setPassword(new String(pass));
			BufferedReader in = new BufferedReader(new InputStreamReader(
					System.in));
			try {
				// if passed directly I got problens at my linux terminal, not
				// sure why
				String pass = in.readLine();
				conn.setPassword(pass);
			} catch (IOException e) {
				System.err.println("Error accessing Stdin: " + e.getMessage());
				System.exit(100);
			}
		}

		try {
			if (parsedArgs.contains(oCertFile)) {
				conn.writeCertificate(oCertFile.getValue());
			} else {
				// to std out
				System.out.println(conn.getCertificateAsString());
			}
		} catch (Exception e) {
			end(e.getMessage());
		}

		// if here everything ended fine. Just store properties.
		conn.saveProperties(propFile);

	}

	private static void end(String message) {
		System.err.println(message);
		System.err.println("Use --help to display help.");
		System.exit(1);
	}

	private static void showUsage() {
		arg.showUsage(MyProxyConsole.class.getSimpleName() + " [options]");
		System.exit(0);
	}

}
