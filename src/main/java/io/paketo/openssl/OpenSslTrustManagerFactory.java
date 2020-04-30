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

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;
import java.util.stream.StreamSupport;

import static io.paketo.openssl.OpenSslProvider.CA_CERTIFICATES_PROPERTY;

abstract class OpenSslTrustManagerFactory extends TrustManagerFactorySpi {

    private static final ConcurrentMap<String, TrustManagerFactory> FACTORY_CACHE = new ConcurrentHashMap<>(1);

    private static final ConcurrentMap<Path, X509ExtendedTrustManager> MANAGER_CACHE = new ConcurrentHashMap<>(1);

    private static final Path SYSTEM = Paths.get("/");

    private final Logger logger = Logger.getLogger(this.getClass().getName());

    private final TrustManagerFactory factory;

    private final Path path;

    private OpenSslTrustManagerFactory(String algorithm, Path path) {
        this.factory = FACTORY_CACHE.computeIfAbsent(algorithm, OpenSslTrustManagerFactory::getFactory);
        this.path = path;
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[]{
            new DelegatingX509ExtendedTrustManager(Arrays.asList(
                MANAGER_CACHE.computeIfAbsent(SYSTEM, this::getJvmManager),
                MANAGER_CACHE.computeIfAbsent(path, this::getOpenSslManager)
            ))
        };
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        factory.init(spec);
        MANAGER_CACHE.remove(SYSTEM);
    }

    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {
        factory.init(ks);
        MANAGER_CACHE.remove(SYSTEM);
    }

    private static Path getCaCertificatesLocation() {
        return Paths.get(System.getProperty(CA_CERTIFICATES_PROPERTY));
    }

    private static TrustManagerFactory getFactory(String algorithm) {
        try {
            return TrustManagerFactory.getInstance(algorithm, "SunJSSE");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private X509ExtendedTrustManager getJvmManager(Path path) {
        logger.info("Adding JVM-configured trust manager");

        for (TrustManager candidate : factory.getTrustManagers()) {
            if (candidate instanceof X509ExtendedTrustManager) {
                return (X509ExtendedTrustManager) candidate;
            }
        }

        throw new RuntimeException("Unable to find JVM-configured trust manager");
    }

    private X509ExtendedTrustManager getOpenSslManager(Path path) {
        logger.info(String.format("Adding OpenSSL-configured trust manager from %s", path));

        try (OpenSslCertificateGenerator generator = new OpenSslCertificateGenerator(path)) {
            KeyStore keyStore = StreamSupport.stream(generator, false)
                .collect(new KeyStoreCollector());

            logger.info(String.format("Loaded %s certificates", keyStore.size()));

            factory.init(keyStore);
            for (TrustManager candidate : factory.getTrustManagers()) {
                if (candidate instanceof X509ExtendedTrustManager) {
                    return (X509ExtendedTrustManager) candidate;
                }
            }

            throw new RuntimeException("Unable to find OpenSSL-configured trust manager");
        } catch (IOException | KeyStoreException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    public static final class PKIXFactory extends OpenSslTrustManagerFactory {

        public PKIXFactory() {
            this(getCaCertificatesLocation());
        }

        PKIXFactory(Path certificates) {
            super("PKIX", certificates);
        }

    }

    public static final class SimpleFactory extends OpenSslTrustManagerFactory {

        public SimpleFactory() {
            this(getCaCertificatesLocation());
        }

        SimpleFactory(Path certificates) {
            super("SunX509", certificates);
        }

    }

}
