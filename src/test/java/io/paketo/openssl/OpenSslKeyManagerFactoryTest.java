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

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

final class OpenSslKeyManagerFactoryTest {

    private final MockWebServer server = new MockWebServer();

    @BeforeEach
    void setUp() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, UnrecoverableKeyException, KeyStoreException,
        KeyManagementException {

        KeyPair clientKeyPair = TestUtils.KeyPair();
        File clientKeyPath = File.createTempFile("client-key", ".pem");
        try (JcaPEMWriter out = new JcaPEMWriter(new FileWriter(clientKeyPath))) {
            out.writeObject(clientKeyPair.getPrivate());
        }

        X509Certificate clientCertificate = TestUtils.Certificate(InetAddress.getByName("localhost").getCanonicalHostName(), clientKeyPair);
        File clientCertificatePath = File.createTempFile("client-certificate", ".pem");
        try (JcaPEMWriter out = new JcaPEMWriter(new FileWriter(clientCertificatePath))) {
            out.writeObject(clientCertificate);
        }

        KeyPair serverKeyPair = TestUtils.KeyPair();
        X509Certificate serverCertificate = TestUtils.Certificate(InetAddress.getByName("localhost").getCanonicalHostName(), serverKeyPair);
        File serverCertificatePath = File.createTempFile("server-certificate", ".pem");
        try (JcaPEMWriter out = new JcaPEMWriter(new FileWriter(serverCertificatePath))) {
            out.writeObject(serverCertificate);
        }

        server.useHttps(TestUtils.SslContext(serverKeyPair, serverCertificate, clientCertificate).getSocketFactory(), false);
        server.requireClientAuth();
        server.enqueue(new MockResponse()
            .setResponseCode(200)
        );
        server.start();

        System.setProperty(OpenSslProvider.PRIVATE_KEY_PROPERTY, clientKeyPath.getPath());
        System.setProperty(OpenSslProvider.CERTIFICATES_PROPERTY, clientCertificatePath.getPath());
        System.setProperty(OpenSslProvider.CA_CERTIFICATES_PROPERTY, serverCertificatePath.getPath());
        Security.insertProviderAt(new OpenSslProvider(), 2);
    }

    @AfterEach
    void tearDown() throws IOException {
        Security.removeProvider("PaketoOpenSSL");
        System.clearProperty(OpenSslProvider.CA_CERTIFICATES_PROPERTY);
        System.clearProperty(OpenSslProvider.PRIVATE_KEY_PROPERTY);
        System.clearProperty(OpenSslProvider.CERTIFICATES_PROPERTY);
        server.close();
    }

    @Test
    void test() throws IOException, NoSuchAlgorithmException {
        Request request = new Request.Builder()
            .url(server.url("/"))
            .build();

        OkHttpClient client = new OkHttpClient.Builder()
            .sslSocketFactory(SSLContext.getDefault().getSocketFactory(), (X509TrustManager) TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).getTrustManagers()[0])
            .build();

        try (Response response = client.newCall(request).execute()) {
            assertThat(response.code()).isEqualTo(200);
        }
    }

}
