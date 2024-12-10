// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.aad.msal4j;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.times;

@ExtendWith(MockitoExtension.class)
class OnBehalfOfTests {

    private String getSuccessfulResponse(String accessToken) {
        return "{\"access_token\":\""+accessToken+"\",\"expires_in\": \""+ 60*60*1000 +"\",\"token_type\":" +
                "\"Bearer\",\"client_id\":\"client_id\",\"Content-Type\":\"text/html; charset=utf-8\"}";
    }

    private HttpResponse expectedResponse(int statusCode, String response) {
        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        headers.put("Content-Type", Collections.singletonList("application/json"));

        HttpResponse httpResponse = new HttpResponse();
        httpResponse.statusCode(statusCode);
        httpResponse.body(response);
        httpResponse.addHeaders(headers);

        return httpResponse;
    }

    @Test
    void OnBehalfOf_InternalCacheLookup_Success() throws Exception {
        DefaultHttpClient httpClientMock = mock(DefaultHttpClient.class);

        when(httpClientMock.send(any(HttpRequest.class))).thenReturn(expectedResponse(200, getSuccessfulResponse("token")));

        ConfidentialClientApplication cca =
                ConfidentialClientApplication.builder("clientId", ClientCredentialFactory.createFromSecret("password"))
                                .authority("https://login.microsoftonline.com/tenant/")
                        .instanceDiscovery(false)
                        .validateAuthority(false)
                        .httpClient(httpClientMock)
                        .build();

        OnBehalfOfParameters parameters = OnBehalfOfParameters.builder(Collections.singleton("scopes"), new UserAssertion(TestHelper.signedToken)).build();

        IAuthenticationResult result = cca.acquireToken(parameters).get();
        IAuthenticationResult result2 = cca.acquireToken(parameters).get();

        //OBO flow should perform an internal cache lookup, so similar parameters should only cause one HTTP client call
        assertEquals(result.accessToken(), result2.accessToken());
        verify(httpClientMock, times(1)).send(any());
    }

    @Test
    void OnBehalfOf_TenantOverride() throws Exception {
        DefaultHttpClient httpClientMock = mock(DefaultHttpClient.class);

        ConfidentialClientApplication cca =
                ConfidentialClientApplication.builder("clientId", ClientCredentialFactory.createFromSecret("password"))
                        .authority("https://login.microsoftonline.com/tenant")
                        .instanceDiscovery(false)
                        .validateAuthority(false)
                        .httpClient(httpClientMock)
                        .build();

        when(httpClientMock.send(any(HttpRequest.class))).thenReturn(expectedResponse(200, getSuccessfulResponse("appTenantToken")));
        OnBehalfOfParameters parameters = OnBehalfOfParameters.builder(Collections.singleton("scopes"), new UserAssertion(TestHelper.signedToken)).build();

        //The two acquireToken calls have the same parameters and should only cause one call from the HTTP client
        IAuthenticationResult resultAppLevelTenant = cca.acquireToken(parameters).get();
        cca.acquireToken(parameters).get();
        assertEquals(1, cca.tokenCache.accessTokens.size());
        verify(httpClientMock, times(1)).send(any());

        when(httpClientMock.send(any(HttpRequest.class))).thenReturn(expectedResponse(200, getSuccessfulResponse("requestTenantToken")));
        parameters = OnBehalfOfParameters.builder(Collections.singleton("scopes"), new UserAssertion(TestHelper.signedToken)).tenant("otherTenant").build();

        //Overriding the tenant parameter in the request should lead to a new token call being made, but followup calls should not
        IAuthenticationResult resultRequestLevelTenant = cca.acquireToken(parameters).get();
        cca.acquireToken(parameters).get();
        assertEquals(2, cca.tokenCache.accessTokens.size());
        verify(httpClientMock, times(2)).send(any());
        assertNotEquals(resultAppLevelTenant.accessToken(), resultRequestLevelTenant.accessToken());
    }
}