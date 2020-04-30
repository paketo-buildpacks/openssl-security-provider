# OpenSSL Security Provider
The Paketo OpenSSL Security Provider is a Java Security Provider that can load OpenSSL artifacts (PEM encoded Private Keys and Certificates) and expose them to applications transparently.

* If the `io.paketo.openssl.ca-certificates=<PATH>` system property is set
  * Adds an additional `TrustManager` containing the certificates from the path, after the configured system `TrustManager`
* If `io.paketo.openssl.private-key=<PATH>` and `io.paketo.openssl.certificates=<PATH>` system properties are set
  * Adds an additional `KeyManager` containing the private key and certificates from the paths, after the configured system `KeyManager`

## License
This library is released under version 2.0 of the [Apache License][a].

[a]: http://www.apache.org/licenses/LICENSE-2.0
