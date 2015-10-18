package puntoAtencion;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PuntoAtencion {
	
	/**
	 * Constantes de protocolo
	 */
	private final static String INFORMAR = "INFORMAR";
	private final static String EMPEZAR = "EMPEZAR";
	private final static String ALGORITMOS = "ALGORITMOS";
	private final static String RTA = "RTA";
	private final static String OK = "OK";
	private final static String CERTPA = "CERTPA";
	private final static String CERTSRV = "CERTSRV";
	private final static String ORDENES = "ORDENES";
	private final static String ERROR = "ERROR";
	private final static String INIT = "INIT";
	
	/**
	 * Constantes de algoritmos
	 */
	private final static String RSA = "RSA";
	private final static String HMACMD5 = "HMACMD5";
	private final static String HMACSHA1 = "HMACSHA1";
	private final static String HMACSHA256 = "HMACSHA256";
	
	/**
	 * Atributos
	 */
	private Socket canal;
	private PrintWriter out;
	private BufferedReader in;
	private String host;
	private int port;
	private String algoritmoHMAC;
	
	public PuntoAtencion(String host, int port, String algoritmoHMAC) {
		this.host=host;
		this.port=port;
		this.algoritmoHMAC=algoritmoHMAC;
	}
	
	private void conectar() throws Exception {
		canal = new Socket(host, port);
		out = new PrintWriter(canal.getOutputStream(), true);
		in = new BufferedReader(new InputStreamReader(canal.getInputStream()));
	}
	
	public void procesar() throws Exception {
		conectar();
		String linea = "";
		out.println(INFORMAR);
		linea = in.readLine();
		if(!linea.equals(EMPEZAR)){
			throw new Exception("Error en el protocolo. Se esperaba: "+EMPEZAR);
		}
		out.println(ALGORITMOS+":"+RSA+":"+algoritmoHMAC);
		linea = in.readLine();
		if(linea.equals(ERROR)||!linea.equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK);
		}
		linea = in.readLine();
	}
	
	public static void main(String[] args) {
		PuntoAtencion puntoAtencion = new PuntoAtencion("localhost", 443, HMACMD5);
		try {
			puntoAtencion.procesar();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
