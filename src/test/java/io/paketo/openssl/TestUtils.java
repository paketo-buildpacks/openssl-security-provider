/*
 * Copyright 2020-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.paketo.openssl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;

final class TestUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static X509Certificate Certificate(String hostname, KeyPair keyPair) throws CertificateException, IOException, OperatorCreationException {
        AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder()
            .find("SHA1withRSA");
        AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder()
            .find(signature);
        ContentSigner signer = new BcRSAContentSignerBuilder(signature, digest)
            .build(PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));

        X509CertificateHolder holder = new X509v3CertificateBuilder(
            new X500Name(String.format("CN=%s", hostname)),
            new BigInteger(64, new SecureRandom()),
            Date.from(Instant.now().minus(Duration.ofMinutes(1))),
            Date.from(Instant.now().plus(Duration.ofMinutes(1))),
            new X500Name(String.format("CN=%s", hostname)),
            SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        )
            .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)).getEncoded())
            .build(signer);

        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
    }

    static KeyPair KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024, new SecureRandom());
        return generator.generateKeyPair();
    }

    static SSLContext SslContext(KeyPair keyPair, X509Certificate certificate, X509Certificate... trustedCertificates) throws KeyStoreException, CertificateException, NoSuchAlgorithmException,
        IOException, UnrecoverableKeyException, KeyManagementException, NoSuchProviderException {

        char[] password = "password".toCharArray();

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, password);

        keyStore.setKeyEntry("private-key", keyPair.getPrivate(), "password".toCharArray(), new Certificate[]{certificate});

        int counter = 0;
        for (X509Certificate trustedCertificate : trustedCertificates) {
            keyStore.setCertificateEntry(String.format("certificate-%3d", counter++), trustedCertificate);
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm(), "SunJSSE");
        keyManagerFactory.init(keyStore, password);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(), "SunJSSE");
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        return sslContext;
    }
}
