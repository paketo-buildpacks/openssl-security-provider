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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.Provider;

/**
 * A {@link Provider} that exposes a {@link KeyManagerFactory} and {@link TrustManagerFactory} based on OpenSSL artifacts.
 */
public final class OpenSslProvider extends Provider {

    static final String CA_CERTIFICATES_PROPERTY = "io.paketo.openssl.ca-certificates";

    static final String CERTIFICATES_PROPERTY = "io.paketo.openssl.certificates";

    static final String PRIVATE_KEY_PROPERTY = "io.paketo.openssl.private-key";

    private static final long serialVersionUID = -1252194694797868474L;

    /**
     * Creates a new instance of the provider.  If {@code io.paketo.openssl.ca-certificates} is set, registers an {@link OpenSslTrustManagerFactory}.  If {@code io.paketo.openssl.certificates} and
     * {@code io.paketo.openssl.private-key} are both set, registers an {@link OpenSslKeyManagerFactory}.
     */
    public OpenSslProvider() {
        super("PaketoOpenSSL", 1.0, "KeyManagerFactory and TrustManagerFactory based on OpenSSL artifacts");

        if (System.getProperty(CA_CERTIFICATES_PROPERTY) != null) {
            put("TrustManagerFactory.SunX509", "io.paketo.openssl.OpenSslTrustManagerFactory$SimpleFactory");
            put("TrustManagerFactory.PKIX", "io.paketo.openssl.OpenSslTrustManagerFactory$PKIXFactory");
            put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
            put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
            put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");
        }

        if (System.getProperty(CERTIFICATES_PROPERTY) != null && System.getProperty(PRIVATE_KEY_PROPERTY) != null) {
            put("KeyManagerFactory.SunX509", "io.paketo.openssl.OpenSslKeyManagerFactory$SunX509");
            put("KeyManagerFactory.NewSunX509", "io.paketo.openssl.OpenSslKeyManagerFactory$X509");
            put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");
        }
    }
}
