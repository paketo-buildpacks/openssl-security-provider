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

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

final class KeyStoreCollector implements Collector<X509Certificate, KeyStore, KeyStore> {

    private int counter = 0;

    @Override
    public BiConsumer<KeyStore, X509Certificate> accumulator() {
        return (keyStore, certificate) -> {
            try {
                String alias = String.format("openssl-%03d", counter++);
                keyStore.setCertificateEntry(alias, certificate);
            } catch (KeyStoreException e) {
                throw new UndeclaredThrowableException(e);
            }
        };
    }

    @Override
    public Set<Characteristics> characteristics() {
        return EnumSet.of(Characteristics.IDENTITY_FINISH, Characteristics.UNORDERED);
    }

    @Override
    public BinaryOperator<KeyStore> combiner() {
        return (a, b) -> {
            try {
                Enumeration<String> aliases = b.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    a.setCertificateEntry(alias, b.getCertificate(alias));
                }
            } catch (KeyStoreException e) {
                throw new UndeclaredThrowableException(e);
            }

            return a;
        };
    }

    @Override
    public Function<KeyStore, KeyStore> finisher() {
        return keyStore -> keyStore;
    }

    @Override
    public Supplier<KeyStore> supplier() {
        return () -> {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null);
                return keyStore;
            } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
                throw new UndeclaredThrowableException(e);
            }
        };
    }

}
