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

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.function.Supplier;

final class OpenSslPrivateKeyGenerator implements Closeable, Supplier<PrivateKey> {

    private static final JcaPEMKeyConverter CONVERTER = new JcaPEMKeyConverter();

    private final PEMParser parser;

    OpenSslPrivateKeyGenerator(Path path) throws IOException {
        this.parser = new PEMParser(Files.newBufferedReader(path));
    }

    @Override
    public void close() throws IOException {
        parser.close();
    }


    @Override
    public PrivateKey get() {
        try {
            Object candidate = parser.readObject();

            if (candidate == null) {
                throw new IllegalArgumentException("no private key found");
            }

            if (!(candidate instanceof PEMKeyPair)) {
                throw new IllegalStateException("encountered an artifact that is not a key pair");
            }

            PrivateKeyInfo privateKeyInfo = ((PEMKeyPair) candidate).getPrivateKeyInfo();
            if (privateKeyInfo == null) {
                throw new IllegalStateException("key pair does not contain a private key");
            }

            return CONVERTER.getPrivateKey(privateKeyInfo);
        } catch (IOException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

}
