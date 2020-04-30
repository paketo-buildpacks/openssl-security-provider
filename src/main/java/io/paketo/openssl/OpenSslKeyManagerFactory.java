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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;
import java.util.stream.StreamSupport;

import static io.paketo.openssl.OpenSslProvider.CERTIFICATES_PROPERTY;
import static io.paketo.openssl.OpenSslProvider.PRIVATE_KEY_PROPERTY;

abstract class OpenSslKeyManagerFactory extends KeyManagerFactorySpi {

    private static final ConcurrentMap<String, KeyManagerFactory> FACTORY_CACHE = new ConcurrentHashMap<>(1);

    private static final ConcurrentMap<Path, X509ExtendedKeyManager> MANAGER_CACHE = new ConcurrentHashMap<>(1);

    private static final Path SYSTEM = Paths.get("/");

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final Path certificatesPath;

    private final KeyManagerFactory factory;

    private final Path privateKeyPath;

    private OpenSslKeyManagerFactory(String algorithm, Path certificatesPath, Path privateKeyPath) {
        this.certificatesPath = certificatesPath;
        this.factory = FACTORY_CACHE.computeIfAbsent(algorithm, OpenSslKeyManagerFactory::getFactory);
        this.privateKeyPath = privateKeyPath;
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return new KeyManager[]{
            new DelegatingX509ExtendedKeyManager(Arrays.asList(
                MANAGER_CACHE.computeIfAbsent(SYSTEM, this::getJvmManager),
                MANAGER_CACHE.computeIfAbsent(certificatesPath, this::getOpenSslManager)
            ))
        };
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        factory.init(spec);
        MANAGER_CACHE.remove(SYSTEM);
    }

    @Override
    protected void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        factory.init(ks, password);
        MANAGER_CACHE.remove(SYSTEM);
    }

    private static Path getCertificatesLocation() {
        return Paths.get(System.getProperty(CERTIFICATES_PROPERTY));
    }

    private static KeyManagerFactory getFactory(String algorithm) {
        try {
            return KeyManagerFactory.getInstance(algorithm, "SunJSSE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private static Path getPrivateKeyLocation() {
        return Paths.get(System.getProperty(PRIVATE_KEY_PROPERTY));
    }

    private X509ExtendedKeyManager getJvmManager(Path path) {
        logger.info("Adding JVM-configured key manager");

        for (KeyManager candidate : factory.getKeyManagers()) {
            if (candidate instanceof X509ExtendedKeyManager) {
                return (X509ExtendedKeyManager) candidate;
            }
        }

        throw new RuntimeException("Unable to find JVM-configured key manager");
    }

    private X509ExtendedKeyManager getOpenSslManager(Path certificatesPath) {
        logger.info(String.format("Adding OpenSSL-configured key manager from %s and %s", certificatesPath, privateKeyPath));

        try (
            OpenSslCertificateGenerator certificateGenerator = new OpenSslCertificateGenerator(certificatesPath);
            OpenSslPrivateKeyGenerator keyGenerator = new OpenSslPrivateKeyGenerator(privateKeyPath)
        ) {
            X509Certificate[] certificates = StreamSupport.stream(certificateGenerator, false)
                .toArray(X509Certificate[]::new);
            PrivateKey privateKey = keyGenerator.get();

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            keyStore.setKeyEntry("openssl-000", privateKey, new char[0], certificates);

            logger.info("Loaded certificates and private key");

            factory.init(keyStore, new char[0]);
            for (KeyManager candidate : factory.getKeyManagers()) {
                if (candidate instanceof X509ExtendedKeyManager) {
                    return (X509ExtendedKeyManager) candidate;
                }
            }

            throw new RuntimeException("Unable to find OpenSSL-configured trust manager");
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    public static final class SunX509 extends OpenSslKeyManagerFactory {

        public SunX509() {
            this(getCertificatesLocation(), getPrivateKeyLocation());
        }

        SunX509(Path certificates, Path privateKey) {
            super("SunX509", certificates, privateKey);
        }

    }

    public static final class X509 extends OpenSslKeyManagerFactory {

        public X509() {
            this(getCertificatesLocation(), getPrivateKeyLocation());
        }

        X509(Path certificates, Path privateKey) {
            super("NewSunX509", certificates, privateKey);
        }

    }
}
