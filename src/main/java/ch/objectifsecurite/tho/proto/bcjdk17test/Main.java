package ch.objectifsecurite.tho.proto.bcjdk17test;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Main {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		final KeyPair keyPair = genKeyPair();

		final X509Certificate certificate = genCertificate(keyPair);

		System.out.println(x509CertificateToPem(certificate));
	}

	private static X509Certificate genCertificate(KeyPair keyPair) throws OperatorCreationException, CertIOException, CertificateException {
		final Instant now = Instant.now();
		final Date notBefore = Date.from(now);
		final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
		final ContentSigner contentSigner =
				new JcaContentSignerBuilder("SHA384WITHRSAANDMGF1")
						.build(keyPair.getPrivate());

		final X500Name x500Name = new X500NameBuilder()
				.addRDN(X509ObjectIdentifiers.commonName, "TestCert")
				.addRDN(X509ObjectIdentifiers.countryName, "Switzerland")
				.addRDN(X509ObjectIdentifiers.stateOrProvinceName, "Vaud")
				.addRDN(X509ObjectIdentifiers.localityName, "Gland")
				.addRDN(X509ObjectIdentifiers.organization, "Objectif-securite")
				.addRDN(X509ObjectIdentifiers.organizationalUnitName, "tests")
				.build();


		KeyUsage ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);

		final X509v3CertificateBuilder certificateBuilder =
				new JcaX509v3CertificateBuilder(x500Name,
						BigInteger.valueOf(42),
						notBefore,
						notAfter,
						x500Name,
						keyPair.getPublic())
						.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
						.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()))
						.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
						.addExtension(Extension.keyUsage, true, ku);
		final X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

		return new JcaX509CertificateConverter()
				.setProvider(new BouncyCastleProvider())
				.getCertificate(certificateHolder);
	}

	private static KeyPair genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		keyPairGenerator.initialize(3072, SecureRandom.getInstance("SHA1PRNG"));
		return keyPairGenerator.generateKeyPair();
	}

	public static String x509CertificateToPem(final X509Certificate cert) throws IOException {
		final StringWriter writer = new StringWriter();
		final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
		pemWriter.writeObject(cert);
		pemWriter.flush();
		pemWriter.close();
		return writer.toString();
	}

	/**
	 * Creates the hash value of the public key.
	 *
	 * @param publicKey of the certificate
	 * @return SubjectKeyIdentifier hash
	 * @throws OperatorCreationException if the algorithm identifier isn't found
	 */
	private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
		final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		final DigestCalculator digCalc =
				new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

		return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
	}

	/**
	 * Creates the hash value of the authority public key.
	 *
	 * @param publicKey of the authority certificate
	 * @return AuthorityKeyIdentifier hash
	 * @throws OperatorCreationException if the algorithm identifier isn't found
	 */
	private static AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)
			throws OperatorCreationException {
		final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		final DigestCalculator digCalc =
				new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

		return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
	}
}
