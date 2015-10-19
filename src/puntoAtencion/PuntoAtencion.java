package puntoAtencion;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;

@SuppressWarnings("deprecation")
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
	private KeyPair keyPair;
	private PublicKey publicKeyServidor;
	private double num1;
	private double num2;

	public PuntoAtencion(String host, int port, String algoritmoHMAC) {
		this.host=host;
		this.port=port;
		this.algoritmoHMAC=algoritmoHMAC;
		KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance(RSA);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void conectar() throws Exception {
		canal = new Socket(host, port);
		out = new PrintWriter(canal.getOutputStream(), true);
		in = new BufferedReader(new InputStreamReader(canal.getInputStream()));
	}

	public void procesar() throws Exception {
		//---------------------------------------
		//Configuración
		//---------------------------------------
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		conectar();
		
		//---------------------------------------
		//Etapa 1
		//---------------------------------------
		String linea = "";
		out.println(INFORMAR);
		linea = in.readLine();
		if(!linea.equals(EMPEZAR)){
			throw new Exception("Error en el protocolo. Se esperaba: "+EMPEZAR+ " Se recibio: "+linea);
		}
		out.println(ALGORITMOS+":"+RSA+":"+algoritmoHMAC);
		linea = in.readLine();
		String[] rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ " Se recibio: "+linea);
		}

		//---------------------------------------
		//Etapa 2
		//---------------------------------------
		num1=Math.random()*1000;
		out.println(num1+":"+CERTPA);
		canal.getOutputStream().write(generarCertificado().getEncoded());
		canal.getOutputStream().flush();
		linea = in.readLine();
		rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ " Se recibio: "+linea);
		}
		linea = in.readLine();
		rta = linea.split(":");
		num2= Double.parseDouble(rta[0]);
		if(!rta[1].equals(CERTSRV)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ " Se recibio: "+linea);
		}
		try{
			CertificateFactory factory=CertificateFactory.getInstance("X.509");
			java.security.cert.Certificate certificadoServidor=factory.generateCertificate(canal.getInputStream());
			publicKeyServidor=certificadoServidor.getPublicKey();
			out.println(RTA+":"+OK);
		} catch(Exception e) {
			out.println(RTA+":"+ERROR);
			throw new Exception("Se produjo un error.");
		}

		//---------------------------------------
		//Etapa 3
		//---------------------------------------
		linea= in.readLine();
		byte[] bytes= Transformacion.destransformar(linea);
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.DECRYPT_MODE, publicKeyServidor);
		byte [] clearText = cipher.doFinal(bytes);
		String numero1= new String(clearText);

		if(num1!=Double.parseDouble(numero1)) {
			out.println(RTA+":"+ERROR);
			throw new Exception("Se produjo un error. Se esperaba: "+num1+ " Se recibio: "+numero1);
		}
		out.println(RTA+":"+OK);

		String envio= num2+"";
		cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		byte [] cipheredText = cipher.doFinal(envio.getBytes());
		out.println(Transformacion.transformar(cipheredText));
		linea = in.readLine();
		rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ " Se recibio: "+linea);
		}

		//---------------------------------------
		//Etapa 4
		//---------------------------------------		
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
		generator.initialize(1024);
		KeyPair desKey =generator.generateKeyPair();

		bytes= desKey.getPublic().getEncoded();
		cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, publicKeyServidor);
		byte[] bytes2= new byte[117];
		for(int i=0;i<bytes2.length;i++) {
			bytes2[i]=bytes[i];
		}
		byte[] bytes3= new byte[45];
		for(int i=0;i<bytes3.length;i++) {
			bytes3[i]=bytes[i+117];
		}
		byte[] cipheredKey = ArrayUtils.addAll(cipher.doFinal(bytes2),cipher.doFinal(bytes3));		
		cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		bytes2= new byte[117];
		for(int i=0;i<bytes2.length;i++) {
			bytes2[i]=cipheredKey[i];
		}
		bytes3= new byte[117];
		for(int i=0;i<bytes3.length;i++) {
			bytes3[i]=cipheredKey[i+117];
		}
		byte[] bytes4= new byte[22];
		for(int i=0;i<bytes4.length;i++) {
			bytes4[i]=cipheredKey[i+234];
		}
		cipheredKey = ArrayUtils.addAll(cipher.doFinal(bytes2),cipher.doFinal(bytes3));
		cipheredKey = ArrayUtils.addAll(cipheredKey,cipher.doFinal(bytes4));
		out.println(INIT+":"+Transformacion.transformar(cipheredKey));
		

		//------------------------------
		//Funciona Hasta esta parte
		//------------------------------
		
		int num=3;
		System.out.println(num);
		envio=ORDENES+":"+num;
		cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, publicKeyServidor);
		cipheredText = cipher.doFinal(envio.getBytes());
		out.println(Transformacion.transformar(cipheredText));

		String data=num+"";
		Mac mac = Mac.getInstance(HMACSHA1);
		mac.init(desKey.getPublic());
		byte[] rawHmac = mac.doFinal(data.getBytes());
		cipheredKey = ArrayUtils.addAll((ORDENES+":").getBytes(),rawHmac);
		cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, publicKeyServidor);
		cipheredText = cipher.doFinal(cipheredKey);
		out.println(Transformacion.transformar(cipheredText));
		linea = in.readLine();
		rta = linea.split(":");
		if(rta[1].equals(ERROR)||!rta[1].equals(OK)) {
			throw new Exception("Se produjo un error. Se esperaba: "+OK+ " Se recibio: "+linea);
		}

	}

	public X509Certificate generarCertificado() throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 30000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 30000));
		certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
				| KeyUsage.keyEncipherment));
		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(
				KeyPurposeId.id_kp_serverAuth));

		certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
				new GeneralName(GeneralName.rfc822Name, "test@test.test")));

		return certGen.generateX509Certificate(keyPair.getPrivate(), "BC");
	}

	public static void main(String[] args) {
		PuntoAtencion puntoAtencion = new PuntoAtencion("localhost", 443, HMACSHA1);
		try {
			puntoAtencion.procesar();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	

}
