// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.aad.msal4j;

import java.net.MalformedURLException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class IntegrationTestHelper {

    static PublicClientApplication createPublicApp(String appID, String authority) {
        try {
            return PublicClientApplication.builder(
                            appID).
                    authority(authority).
                    build();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    static void assertTokenResultNotNull(IAuthenticationResult result, boolean checkAccessToken, boolean checkIDToken) {
        assertNotNull(result);
        if (checkAccessToken) assertNotNull(result.accessToken());
        if (checkIDToken) assertNotNull(result.idToken());
    }
}
