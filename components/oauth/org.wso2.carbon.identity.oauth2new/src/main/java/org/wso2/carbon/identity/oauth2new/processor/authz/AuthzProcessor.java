/*
 *Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.carbon.identity.oauth2new.processor.authz;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.oauth2new.HandlerManager;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.authz.AuthzApprovedRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.request.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2AuthzResponse;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2InboundRequestProcessor;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public abstract class AuthzProcessor extends OAuth2InboundRequestProcessor {

    public int getPriority() {
        return 0;
    }

    public String getCallbackPath(InboundAuthenticationContext context) throws FrameworkException {
        return null;
    }

    public String getRelyingPartyId() {
        return null;
    }

    public boolean canHandle(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {
        return false;
    }

    public InboundAuthenticationResponse process(InboundAuthenticationRequest authenticationRequest)
            throws FrameworkException {

        if(!(authenticationRequest instanceof OAuth2AuthzRequest ||
                authenticationRequest instanceof AuthzApprovedRequest)) {
            throw OAuth2RuntimeException.error("InboundAuthenticationRequest object neither an instance of " +
                    "OAuth2AuthzRequest nor an instance of  AuthzApprovedRequest");
        }

        String tenantDomain = authenticationRequest.getParameterValue(MultitenantConstants.TENANT_DOMAIN);
        OAuth2AuthzMessageContext messageContext = new OAuth2AuthzMessageContext(
                (OAuth2AuthzRequest)authenticationRequest, tenantDomain, new HashMap<String,String>());

        if(authenticationRequest instanceof OAuth2AuthzRequest) {
            return initiateApproval(messageContext);
        } else {
            processApproval(messageContext);
        }

        return issue(messageContext);
    }

    /**
     * Initiate the request to authenticate resource owner and obtain authorization decision
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint
     * @throws OAuth2RuntimeException Exception occurred while issuing authorization endpoint response
     */
    protected OAuth2AuthzResponse initiateApproval(OAuth2AuthzMessageContext messageContext)
            throws OAuth2RuntimeException {

        return null;
    }

    /**
     * Process the response from resource owner approval process and establish the authorization decision
     *
     * @param messageContext The runtime message context
     * @throws OAuth2Exception Exception occurred while processing resource owner approval
     */
    protected void processApproval(OAuth2AuthzMessageContext messageContext) throws OAuth2Exception {

    }

    /**
     * Issues the authorization endpoint response
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint response
     * @throws OAuth2RuntimeException Exception occurred while issuing authorization endpoint response
     */
    protected OAuth2AuthzResponse issue(OAuth2AuthzMessageContext messageContext) throws OAuth2RuntimeException {

        AccessToken accessToken = HandlerManager.getInstance().issueAccessToken(messageContext);
        return buildAuthzResponse(accessToken, messageContext);
    }

    protected OAuth2AuthzResponse buildAuthzResponse(AccessToken accessToken,
                                                     OAuth2AuthzMessageContext messageContext) {


        long expiry = 0;
        if(accessToken.getAccessTokenValidity() > 0) {
            expiry = accessToken.getAccessTokenValidity()/1000;
        } else {
            expiry = Long.MAX_VALUE/1000;
        }

        // read redirect_uri from application.mgt
        String redirectURI = null;

        OAuthASResponse.OAuthAuthorizationResponseBuilder oltuRespBuilder = OAuthASResponse
                .authorizationResponse(null, HttpServletResponse.SC_FOUND)
                .location(redirectURI)
                .setAccessToken(accessToken.getAccessToken())
                .setExpiresIn(Long.toString(expiry))
                .setParam(OAuth.OAUTH_TOKEN_TYPE, OAuth.OAUTH_HEADER_NAME)
                .setParam(OAuth.OAUTH_STATE, messageContext.getRequest().getState())
                .setParam(OAuth.OAUTH_SCOPE, OAuth2Util.buildScopeString(accessToken.getScopes()));

        // Have to check if refresh grant is allowed
        if(issueRefreshToken(messageContext)) {
            oltuRespBuilder.setParam(OAuth.OAUTH_REFRESH_TOKEN, accessToken.getRefreshToken());
        }

        OAuthResponse oltuResponse;
        try {
            oltuResponse = oltuRespBuilder.buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }

        OAuth2TokenResponse.InboundAuthenticationResponseBuilder builder = new OAuth2AuthzResponse
                .InboundAuthenticationResponseBuilder();
        builder.setStatusCode(oltuResponse.getResponseStatus())
                .setHeaders(oltuResponse.getHeaders())
                .setBody(oltuResponse.getBody())
                .setRedirectURL(oltuResponse.getLocationUri());
        return (OAuth2AuthzResponse)builder.build();
    }

}
