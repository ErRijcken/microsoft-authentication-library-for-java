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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class TestHelper {

    //Signed JWT which should be enough to pass the parsing/validation in the library, useful if a unit test needs an
    // assertion but that is not the focus of the test
    static String signedAssertion = generateToken();
    private static final String successfulResponseFormat = "{\"access_token\":\"%s\",\"id_token\":\"%s\",\"refresh_token\":\"%s\"," +
            "\"client_id\":\"%s\",\"client_info\":\"%s\"," +
            "\"expires_on\": %d ,\"expires_in\": %d," +
            "\"token_type\":\"Bearer\"}";

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

    //Maps various values to the successfulResponseFormat string to create a valid token response
    static String getSuccessfulTokenResponse(HashMap<String, String> responseValues) {
        //Will default to expiring in one hour if expiry time values are not set
        long expiresIn = responseValues.containsKey("expires_in") ?
                Long.parseLong(responseValues.get("expires_in")) :
                3600;
        long expiresOn = responseValues.containsKey("expires_on")
                ? Long.parseLong(responseValues.get("expires_0n")) :
                (System.currentTimeMillis() / 1000) + expiresIn;

        return String.format(successfulResponseFormat,
                responseValues.getOrDefault("access_token", "access_token"),
                responseValues.getOrDefault("id_token", "id_token"),
                responseValues.getOrDefault("refresh_token", "refresh_token"),
                responseValues.getOrDefault("client_id", "client_id"),
                responseValues.getOrDefault("client_info", "client_info"),
                expiresOn,
                expiresIn
        );
    }

    //Creates a valid HttpResponse that can be used when mocking HttpClient.send()
    static HttpResponse expectedResponse(int statusCode, String response) {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Content-Type", Collections.singletonList("application/json"));

        HttpResponse httpResponse = new HttpResponse();
        httpResponse.statusCode(statusCode);
        httpResponse.body(response);
        httpResponse.addHeaders(headers);

        return httpResponse;
    }
}
