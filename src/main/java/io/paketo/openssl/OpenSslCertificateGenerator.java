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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Spliterator;
import java.util.function.Consumer;

final class OpenSslCertificateGenerator implements Closeable, Spliterator<X509Certificate> {

    private static final JcaX509CertificateConverter CONVERTER = new JcaX509CertificateConverter();

    private final PEMParser parser;

    OpenSslCertificateGenerator(Path path) throws IOException {
        this.parser = new PEMParser(Files.newBufferedReader(path));
    }

    @Override
    public int characteristics() {
        return DISTINCT | IMMUTABLE | NONNULL;
    }

    @Override
    public void close() throws IOException {
        parser.close();
    }

    @Override
    public long estimateSize() {
        return Long.MAX_VALUE;
    }

    @Override
    public boolean tryAdvance(Consumer<? super X509Certificate> action) {
        try {
            Object candidate = parser.readObject();

            if (candidate == null) {
                return false;
            }

            if (!(candidate instanceof X509CertificateHolder)) {
                throw new IllegalStateException("encountered an artifact that is not a certificate");
            }

            action.accept(CONVERTER.getCertificate((X509CertificateHolder) candidate));
            return true;
        } catch (CertificateException | IOException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    @Override
    public Spliterator<X509Certificate> trySplit() {
        return null;
    }
}
