/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2new.processor.token;


import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.oauth2new.HandlerManager;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.OAuth2TokenRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;
import org.wso2.carbon.identity.oauth2new.common.ClientType;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2InboundRequestProcessor;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/*
 * InboundRequestProcessor for OAuth2 Token Endpoint
 */
public abstract class TokenProcessor extends OAuth2InboundRequestProcessor {

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public String getCallbackPath(InboundAuthenticationContext context) throws FrameworkException {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public boolean canHandle(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {
        return false;
    }

    @Override
    public InboundAuthenticationResponse process(InboundAuthenticationRequest authenticationRequest)
            throws FrameworkException {

        if(!(authenticationRequest instanceof OAuth2TokenRequest)) {
            throw OAuth2RuntimeException.error("InboundAuthenticationRequest object not an instance of " +
                    "OAuth2TokenRequest type");
        }

        String tenantDomain = authenticationRequest.getParameterValue(MultitenantConstants.TENANT_DOMAIN);
        OAuth2TokenMessageContext messageContext = new OAuth2TokenMessageContext(
                (OAuth2TokenRequest)authenticationRequest, tenantDomain, new HashMap<String,String>());

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            authenticateClient(messageContext);
        }

        validateGrant(messageContext);

        return issue(messageContext);

    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected ClientType clientType(OAuth2TokenMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws OAuth2Exception
     */
    protected String authenticateClient(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return HandlerManager.getInstance().handleClientAuthentication(messageContext);
    }

    /**
     * Validates the Authorization Grant
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the authorization grant is valid
     * @throws OAuth2Exception
     */
    protected void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        /* Method not implemented */
    }

    /**
     * Issues the access token
     *
     * @param messageContext The runtime message context
     * @return OAuth2 access token response
     * @throws OAuth2Exception
     */
    protected OAuth2TokenResponse issue(OAuth2TokenMessageContext messageContext) throws OAuth2RuntimeException {

        AccessToken accessToken = HandlerManager.getInstance().issueAccessToken(messageContext);
        return buildTokenResponse(accessToken, messageContext);
    }

    protected OAuth2TokenResponse buildTokenResponse(AccessToken accessToken, OAuth2TokenMessageContext messageContext) {

        long expiry = 0;
        if(accessToken.getAccessTokenValidity() > 0) {
            expiry = accessToken.getAccessTokenValidity()/1000;
        } else {
            expiry = Long.MAX_VALUE/1000;
        }

        // Have to check if refresh grant is allowed

        String refreshToken = null;
        if(issueRefreshToken(messageContext)) {
            refreshToken = accessToken.getRefreshToken();
        }

        OAuthASResponse.OAuthTokenResponseBuilder oltuRespBuilder = OAuthASResponse
                .tokenResponse(HttpServletResponse.SC_OK)
                .setAccessToken(accessToken.getAccessToken())
                .setRefreshToken(refreshToken)
                .setExpiresIn(Long.toString(expiry))
                .setTokenType(OAuth.OAUTH_HEADER_NAME);
        oltuRespBuilder.setScope(OAuth2Util.buildScopeString(accessToken.getScopes()));

        OAuthResponse oltuASResponse = null;
        try {
            oltuASResponse = oltuRespBuilder.buildJSONMessage();
        } catch (OAuthSystemException e1) {
            throw OAuth2RuntimeException.error("Error occurred while generating Bearer token");
        }

        OAuth2TokenResponse.InboundAuthenticationResponseBuilder builder = new OAuth2TokenResponse
                .InboundAuthenticationResponseBuilder();
        builder.setStatusCode(oltuASResponse.getResponseStatus());
        builder.setHeaders(oltuASResponse.getHeaders());
        builder.setBody(oltuASResponse.getBody());
        builder.addHeader(OAuth2.Header.CACHE_CONTROL,
                OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
        builder.addHeader(OAuth2.Header.PRAGMA,
                OAuth2.HeaderValue.PRAGMA_NO_CACHE);
        return (OAuth2TokenResponse)builder.build();

    }
}
