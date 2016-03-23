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

package org.wso2.carbon.identity.oidc.processor;

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ConsentException;
import org.wso2.carbon.identity.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.oauth2new.processor.authz.TokenResponseProcessor;
import org.wso2.carbon.identity.oauth2new.util.OAuth2ConsentStore;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;
import org.wso2.carbon.identity.oidc.IDTokenBuilder;
import org.wso2.carbon.identity.oidc.OIDC;
import org.wso2.carbon.identity.oidc.bean.message.authz.OIDCAuthzRequest;
import org.wso2.carbon.identity.oidc.handler.OIDCHandlerManager;

import java.util.Set;

public class OIDCTokenResponseProcessor extends TokenResponseProcessor {

    public String getName() {
        return "OIDCTokenResponseProcessor";
    }

    public boolean canHandle(InboundRequest inboundRequest) throws FrameworkException {
        if(super.canHandle(inboundRequest)) {
            Set<String> scopes = OAuth2Util.buildScopeSet(inboundRequest.getParameter(OAuth.OAUTH_SCOPE));
            if (scopes.contains(OIDC.OPENID_SCOPE)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public InboundResponse process(InboundRequest inboundRequest) throws FrameworkException {

        OAuth2AuthzMessageContext messageContext = (OAuth2AuthzMessageContext)getContextIfAvailable(inboundRequest);

        if(messageContext.getAuthzUser() == null) { // authentication response

            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHN_REQUEST, inboundRequest);
            AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext);

            AuthenticatedUser authenticatedUser = null;
            if(authnResult.isAuthenticated()) {
                authenticatedUser = authnResult.getSubject();
                messageContext.setAuthzUser(authenticatedUser);

            } else {
                throw OAuth2AuthnException.error("Resource owner authentication failed");
            }

            boolean isConsentRequired = ((OIDCAuthzRequest)messageContext.getRequest()).isConsentRequired();
            boolean isPromptNone = ((OIDCAuthzRequest)messageContext.getRequest()).isPromptNone();

            if(isConsentRequired){
                return initiateResourceOwnerConsent(messageContext).build();
            } else if (!OAuth2ServerConfig.getInstance().isSkipConsentPage()) {

                String spName = ((ServiceProvider) messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER)).getApplicationName();

                if (!OAuth2ConsentStore.getInstance().hasUserApprovedAppAlways(authenticatedUser, spName)) {
                    if(!isPromptNone) {
                        return initiateResourceOwnerConsent(messageContext).build();
                    } else {
                        throw OAuth2ConsentException.error("Prompt contains none, but user approval required");
                    }
                } else {
                    messageContext.addParameter(OAuth2.CONSENT, "ApproveAlways");
                }
            } else {
                messageContext.addParameter(OAuth2.CONSENT, "SkipOAuth2Consent");
            }

        }

        // if this line is reached that means this is a consent response or consent is skipped due config or approve
        // always. We set the inbound request to message context only if it has gone through consent process
        // if consent consent was skipped due to configuration or approve always,
        // authenticated request and authorized request are the same
        if(!StringUtils.equals("ApproveAlways", (String)messageContext.getParameter(OAuth2.CONSENT)) &&
                !StringUtils.equals("SkipOAuth2Consent", (String)messageContext.getParameter(OAuth2.CONSENT))) {
            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHZ_REQUEST, inboundRequest);
            processConsent(messageContext);
        }
        return buildAuthzResponse(messageContext).build();
    }

    protected InboundResponse.InboundResponseBuilder buildAuthzResponse(
            OAuth2AuthzMessageContext messageContext) {

        InboundResponse.InboundResponseBuilder builder =
                super.buildAuthzResponse(messageContext);
        AuthenticationResult authenticationResult = (AuthenticationResult)messageContext.getParameter(
                InboundConstants.RequestProcessor.AUTHENTICATION_RESULT);
        if(StringUtils.isNotBlank(authenticationResult.getAuthenticatedIdPs())){
            builder.addParameter(InboundConstants.LOGGED_IN_IDPS,
                    authenticationResult.getAuthenticatedIdPs());
        }
        if(messageContext.getRequest().getResponseType().contains("id_token")) {
            buildIDToken(builder, messageContext);
        }
        return builder;
    }

    protected InboundResponse.InboundResponseBuilder buildIDToken(
            InboundResponse.InboundResponseBuilder builder,
            OAuth2AuthzMessageContext messageContext) {

        IDTokenBuilder idTokenBuilder = OIDCHandlerManager.getInstance().buildIDToken(messageContext);
        String idToken = idTokenBuilder.build();
        return builder.addParameter("id_token", idToken);
    }

    protected boolean issueRefreshToken(OAuth2AuthzMessageContext messageContext) {
        return false;
    }

}
