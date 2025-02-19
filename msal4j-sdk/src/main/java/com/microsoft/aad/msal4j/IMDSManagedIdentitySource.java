// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.aad.msal4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;

class IMDSManagedIdentitySource extends AbstractManagedIdentitySource{

    // IMDS constants. Docs for IMDS are available here https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token#get-a-token-using-http
    private static final Logger LOG = LoggerFactory.getLogger(IMDSManagedIdentitySource.class);
    private static final URI DEFAULT_IMDS_ENDPOINT;

    static {
        try {
            DEFAULT_IMDS_ENDPOINT = new URI("http://169.254.169.254/metadata/identity/oauth2/token");
        } catch (URISyntaxException e) {
            throw new MsalServiceException(e.getMessage(), MsalError.INVALID_MANAGED_IDENTITY_ENDPOINT, ManagedIdentitySourceType.IMDS);
        }
    }

    private static final String IMDS_TOKEN_PATH = "/metadata/identity/oauth2/token";
    private static final String IMDS_API_VERSION = "2018-02-01";

    private URI imdsEndpoint;

    public IMDSManagedIdentitySource(MsalRequest msalRequest,
                                     ServiceBundle serviceBundle) {
        super(msalRequest, serviceBundle, ManagedIdentitySourceType.IMDS);
        IEnvironmentVariables environmentVariables = getEnvironmentVariables();

        if (!StringHelper.isNullOrBlank(environmentVariables.getEnvironmentVariable(Constants.AZURE_POD_IDENTITY_AUTHORITY_HOST))){
            LOG.info(String.format("[Managed Identity] Environment variable AZURE_POD_IDENTITY_AUTHORITY_HOST for IMDS returned endpoint: %s", environmentVariables.getEnvironmentVariable(Constants.AZURE_POD_IDENTITY_AUTHORITY_HOST)));
            try {
                imdsEndpoint = new URI(environmentVariables.getEnvironmentVariable(Constants.AZURE_POD_IDENTITY_AUTHORITY_HOST));
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }

            StringBuilder builder = new StringBuilder(environmentVariables.getEnvironmentVariable(Constants.AZURE_POD_IDENTITY_AUTHORITY_HOST));
            builder.append("/" + IMDS_TOKEN_PATH);
            try {
                imdsEndpoint = new URI(builder.toString());
            } catch (URISyntaxException e) {
                throw new MsalServiceException(String.format(MsalErrorMessage.MANAGED_IDENTITY_ENDPOINT_INVALID_URI_ERROR,
                        Constants.AZURE_POD_IDENTITY_AUTHORITY_HOST,
                        builder.toString(),
                        ManagedIdentitySourceType.IMDS), MsalError.INVALID_MANAGED_IDENTITY_ENDPOINT,
                        ManagedIdentitySourceType.IMDS);
            }
        }
        else
        {
            LOG.info("[Managed Identity] Unable to find AZURE_POD_IDENTITY_AUTHORITY_HOST environment variable for IMDS, using the default endpoint.");
            imdsEndpoint = DEFAULT_IMDS_ENDPOINT;
        }

        LOG.info(String.format("[Managed Identity] Creating IMDS managed identity source. Endpoint URI: %s", imdsEndpoint));
    }

    @Override
    public void createManagedIdentityRequest(String resource) {
        managedIdentityRequest.baseEndpoint = imdsEndpoint;
        managedIdentityRequest.method = HttpMethod.GET;

        managedIdentityRequest.headers = new HashMap<>();
        managedIdentityRequest.headers.put("Metadata", "true");

        managedIdentityRequest.queryParameters = new HashMap<>();
        managedIdentityRequest.queryParameters.put("api-version", Collections.singletonList(IMDS_API_VERSION));
        managedIdentityRequest.queryParameters.put("resource", Collections.singletonList(resource));

        if (this.idType != null && !StringHelper.isNullOrBlank(this.userAssignedId)) {
            LOG.info("[Managed Identity] Adding user assigned ID to the request for IMDS Managed Identity.");
            managedIdentityRequest.addUserAssignedIdToQuery(this.idType, this.userAssignedId);
        }
    }

    @Override
    public ManagedIdentityResponse handleResponse(
            ManagedIdentityParameters parameters,
            IHttpResponse response)
    {
        // handle error status codes indicating managed identity is not available
        String baseMessage;

        if(response.statusCode()== HttpURLConnection.HTTP_BAD_REQUEST){
            baseMessage = MsalErrorMessage.IDENTITY_UNAVAILABLE_ERROR;
        }else if(response.statusCode()== HttpURLConnection.HTTP_BAD_GATEWAY ||
                response.statusCode()== HttpURLConnection.HTTP_GATEWAY_TIMEOUT){
            baseMessage = MsalErrorMessage.GATEWAY_ERROR;
        }else{
            baseMessage = null;
        }

        if (baseMessage != null)
        {
            String message = createRequestFailedMessage(response, baseMessage);

            String errorContentMessage = getMessageFromErrorResponse(response);

            message = message + " " + errorContentMessage;

            LOG.error(String.format("Error message: %s Http status code: %s", message, response.statusCode()));
            throw new MsalServiceException(message, MsalError.MANAGED_IDENTITY_REQUEST_FAILED,
                    ManagedIdentitySourceType.IMDS);
        }

        // Default behavior to handle successful scenario and general errors.
        return super.handleResponse(parameters, response);
    }

    private static String createRequestFailedMessage(IHttpResponse response, String message)
    {
        StringBuilder messageBuilder = new StringBuilder();

        messageBuilder.append(StringHelper.isNullOrBlank(message) ? MsalErrorMessage.DEFAULT_MESSAGE : message);
        messageBuilder.append("Status: ");
        messageBuilder.append(response.statusCode());

        if (response.body() != null)
        {
            messageBuilder.append("Content:").append(response.body());
        }

        messageBuilder.append("Headers:");

        for(String key : response.headers().keySet())
        {
            messageBuilder.append(key).append(response.headers().get(key));
        }

        return messageBuilder.toString();
    }
}
