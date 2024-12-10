// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.aad.msal4j;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

class TestHelper {

    //Signed JWT which should be enough to pass the parsing/validation in the library, useful if a unit test needs an
    // assertion in a request or token in a response but that is not the focus of the test
    static String signedToken = generateToken();

    static String readResource(Class<?> classInstance, String resource) {
        try {
            return new String(Files.readAllBytes(Paths.get(classInstance.getResource(resource).toURI())));
        } catch (IOException | URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    static void deleteFileContent(Class<?> classInstance, String resource)
            throws URISyntaxException, IOException {
        FileWriter fileWriter = new FileWriter(
                new File(Paths.get(classInstance.getResource(resource).toURI()).toString()),
                false);

        fileWriter.write("");
        fileWriter.close();
    }

    static String generateToken() {
        try {
            RSAKey rsaJWK = new RSAKeyGenerator(2048)
                    .keyID("kid")
                    .generate();
            JWSObject jwsObject = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                    new Payload("payload"));

            jwsObject.sign(new RSASSASigner(rsaJWK));

            return jwsObject.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
