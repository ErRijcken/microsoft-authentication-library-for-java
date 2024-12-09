// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.aad.msal4j;

import labapi.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Collections;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OnBehalfOfIT {

    private Config cfg;

    @ParameterizedTest
    @MethodSource("com.microsoft.aad.msal4j.EnvironmentsProvider#createData")
    void acquireTokenWithOBO_Managed(String environment) throws Exception {
        cfg = new Config(environment);
        String accessToken = this.getAccessToken();

        final String clientId = cfg.appProvider.getOboAppId();
        final String password = cfg.appProvider.getOboAppPassword();

        ConfidentialClientApplication cca =
                ConfidentialClientApplication.builder(clientId, ClientCredentialFactory.createFromSecret(password)).
                        authority(cfg.tenantSpecificAuthority()).
                        build();

        IAuthenticationResult result =
                cca.acquireToken(OnBehalfOfParameters.builder(
                        Collections.singleton(cfg.graphDefaultScope()),
                        new UserAssertion(accessToken)).build()).
                        get();

        assertResultNotNull(result);
    }

    @ParameterizedTest
    @MethodSource("com.microsoft.aad.msal4j.EnvironmentsProvider#createData")
    void acquireTokenWithOBO_testCache(String environment) throws Exception {
        cfg = new Config(environment);
        String accessToken = this.getAccessToken();

        final String clientId = cfg.appProvider.getOboAppId();
        final String password = cfg.appProvider.getOboAppPassword();

        ConfidentialClientApplication cca =
                ConfidentialClientApplication.builder(clientId, ClientCredentialFactory.createFromSecret(password)).
                        authority(cfg.tenantSpecificAuthority()).
                        build();

        IAuthenticationResult result1 =
                cca.acquireToken(OnBehalfOfParameters.builder(
                        Collections.singleton(TestConstants.USER_READ_SCOPE),
                        new UserAssertion(accessToken)).build()).
                        get();

        assertResultNotNull(result1);

        // Same scope and userAssertion, should return cached tokens
        IAuthenticationResult result2 =
                cca.acquireToken(OnBehalfOfParameters.builder(
                        Collections.singleton(TestConstants.USER_READ_SCOPE),
                        new UserAssertion(accessToken)).build()).
                        get();

        assertEquals(result1.accessToken(), result2.accessToken());

        // Scope 2, should return new token
        IAuthenticationResult result3 =
                cca.acquireToken(OnBehalfOfParameters.builder(
                        Collections.singleton(cfg.graphDefaultScope()),
                        new UserAssertion(accessToken)).build()).
                        get();

        assertResultNotNull(result3);
        assertNotEquals(result2.accessToken(), result3.accessToken());

        // Scope 2, should return cached token
        IAuthenticationResult result4 =
                cca.acquireToken(OnBehalfOfParameters.builder(
                        Collections.singleton(cfg.graphDefaultScope()),
                        new UserAssertion(accessToken)).build()).
                        get();

        assertEquals(result3.accessToken(), result4.accessToken());

        // skipCache=true, should return new token
        IAuthenticationResult result5 =
                cca.acquireToken(
                        OnBehalfOfParameters.builder(
                                Collections.singleton(cfg.graphDefaultScope()),
                                new UserAssertion(accessToken))
                                .skipCache(true)
                                .build()).
                        get();

        assertResultNotNull(result5);
        assertNotEquals(result5.accessToken(), result4.accessToken());
        assertNotEquals(result5.accessToken(), result2.accessToken());


        String newAccessToken = this.getAccessToken();
        // New new UserAssertion, should return new token
        IAuthenticationResult result6 =
                cca.acquireToken(
                        OnBehalfOfParameters.builder(
                                Collections.singleton(cfg.graphDefaultScope()),
                                new UserAssertion(newAccessToken))
                                .build()).
                        get();

        assertResultNotNull(result6);
        assertNotEquals(result6.accessToken(), result5.accessToken());
        assertNotEquals(result6.accessToken(), result4.accessToken());
        assertNotEquals(result6.accessToken(), result2.accessToken());
    }

    @Test
    void acquireTokenWithOBO_TenantOverride() throws Exception {
        cfg = new Config(AzureEnvironment.AZURE);
        String accessToken = this.getAccessToken();

        final String clientId = cfg.appProvider.getOboAppId();
        final String password = cfg.appProvider.getOboAppPassword();

        ConfidentialClientApplication cca =
                ConfidentialClientApplication.builder(clientId, ClientCredentialFactory.createFromSecret(password)).
                        authority(cfg.tenantSpecificAuthority()).
                        build();

        //This token should be cached with the tenant-specific authority set at the application level
        IAuthenticationResult resultNoOverride = cca.acquireToken(OnBehalfOfParameters.builder(
                                Collections.singleton(cfg.graphDefaultScope()),
                                new UserAssertion(accessToken)).build()).
                        get();

        //This token should be cached with an 'organizations' authority set at the request level
        IAuthenticationResult resultOrganizations = cca.acquireToken(OnBehalfOfParameters.builder(
                                Collections.singleton(cfg.graphDefaultScope()),
                                new UserAssertion(accessToken))
                                .tenant("organizations")
                                .build()).
                        get();

        //This token should come from the cache and match the token with the 'organizations' authority
        IAuthenticationResult resultOrganizationsCached = cca.acquireToken(OnBehalfOfParameters.builder(
                                Collections.singleton(cfg.graphDefaultScope()),
                                new UserAssertion(accessToken))
                                .tenant("organizations")
                                .build()).
                        get();

        assertResultNotNull(resultNoOverride);
        assertResultNotNull(resultOrganizations);
        assertResultNotNull(resultOrganizationsCached);

        assertNotEquals(resultNoOverride.accessToken(), resultOrganizations.accessToken());
        assertEquals(resultOrganizations.accessToken(), resultOrganizationsCached.accessToken());
    }

    private void assertResultNotNull(IAuthenticationResult result) {
        assertNotNull(result);
        assertNotNull(result.accessToken());
    }

    private String getAccessToken() throws Exception {

        LabUserProvider labUserProvider = LabUserProvider.getInstance();
        User user = labUserProvider.getDefaultUser(cfg.azureEnvironment);

        String clientId = cfg.appProvider.getAppId();
        String apiReadScope = cfg.appProvider.getOboAppIdURI() + "/user_impersonation";
        PublicClientApplication pca = PublicClientApplication.builder(
                clientId).
                authority(cfg.tenantSpecificAuthority()).
                build();

        IAuthenticationResult result = pca.acquireToken(
                UserNamePasswordParameters.builder(Collections.singleton(apiReadScope),
                        user.getUpn(),
                        user.getPassword().toCharArray()).build()).get();

        return result.accessToken();
    }
}