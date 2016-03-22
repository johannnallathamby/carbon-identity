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

package org.wso2.carbon.identity.oauth2new.processor.authz;

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.AuthenticationFrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContextCache;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContextCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContextCacheKey;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequestProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2AuthnException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ConsentException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2InternalException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.oauth2new.util.OAuth2ConsentStore;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.UUID;

public abstract class ResourceOwnerApprovedRequestProcessor extends InboundAuthenticationRequestProcessor {

    @Override
    public String getName() {
        return "ResourceOwnerApprovedRequestProcessor";
    }

    @Override
    public String getCallbackPath(InboundAuthenticationContext context) throws AuthenticationFrameworkRuntimeException {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {

        InboundAuthenticationContext context = getContextIfAvailable(authenticationRequest);
        if(context != null) {
            if(context.getRequest() instanceof OAuth2AuthzRequest){
                return true;
            }
        }
        return false;
    }

    @Override
    public InboundAuthenticationResponse process(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {

        OAuth2AuthzMessageContext messageContext = (OAuth2AuthzMessageContext)getContextIfAvailable(authenticationRequest);

        if(messageContext.getAuthzUser() == null) { // authentication response

            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHN_REQUEST, authenticationRequest);
            AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext);

            AuthenticatedUser authenticatedUser = null;
            if(authnResult.isAuthenticated()) {
                authenticatedUser = authnResult.getSubject();
                messageContext.setAuthzUser(authenticatedUser);

            } else {
                throw OAuth2AuthnException.error("Resource owner authentication failed");
            }

            if (!OAuth2ServerConfig.getInstance().isSkipConsentPage()) {

                String spName = ((ServiceProvider) messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER)).getApplicationName();

                if (!OAuth2ConsentStore.getInstance().hasUserApprovedAppAlways(authenticatedUser, spName)) {
                    return getConsentBuilder(messageContext).build();
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
            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHZ_REQUEST, authenticationRequest);
            processConsent(messageContext);
        }
        return getAuthzResponseBuilder(messageContext).build();
    }

    /**
     * Initiate the request to obtain authorization decision from resource owner
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint
     * @throws OAuth2RuntimeException Exception occurred while issuing authorization endpoint response
     */
    protected InboundAuthenticationResponse.InboundAuthenticationResponseBuilder getConsentBuilder(
            OAuth2AuthzMessageContext messageContext) throws OAuth2RuntimeException {

        String sessionDataKeyConsent = UUID.randomUUID().toString();
        addAuthenticationContextToCache(sessionDataKeyConsent, messageContext);
        String consentPage = OAuth2ServerConfig.getInstance().getOauth2ConsentPageUrl();
        String queryString = null;
        try {
            queryString = IdentityUtil.buildQueryString(messageContext.getRequest().getParameters());
        } catch (UnsupportedEncodingException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
        String spName = ((ServiceProvider)messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER)).getApplicationName();
        try {
            consentPage += queryString + OAuth2.LOGGED_IN_USER + "=" + URLEncoder.encode(messageContext.getAuthzUser().getAuthenticatedSubjectIdentifier(),
                    "UTF-8") + "&application=" + URLEncoder.encode(spName, "ISO-8859-1") +
                    "&" + OAuth.OAUTH_SCOPE + "=" + URLEncoder.encode(OAuth2Util.buildScopeString(messageContext.getApprovedScopes()),
                    "ISO-8859-1") + "&" + OAuth2.SESSION_DATA_KEY_CONSENT + "=" + URLEncoder
                    .encode(sessionDataKeyConsent, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw OAuth2RuntimeException.error(e.getMessage(), e);
        }
        InboundAuthenticationResponse.InboundAuthenticationResponseBuilder builder = new
                InboundAuthenticationResponse.InboundAuthenticationResponseBuilder();
        builder.setStatusCode(HttpServletResponse.SC_FOUND);
        builder.setRedirectURL(consentPage);
        return builder;
    }

    private void addAuthenticationContextToCache(String key, OAuth2MessageContext messageContext) {
        InboundAuthenticationContextCache cache = InboundAuthenticationContextCache.getInstance();
        cache.addToCache(new InboundAuthenticationContextCacheKey(key),
                new InboundAuthenticationContextCacheEntry(messageContext));
    }

    /**
     * Process the response from resource owner approval process and establish the authorization decision
     *
     * @param messageContext The runtime message context
     * @throws OAuth2Exception Exception occurred while processing resource owner approval
     */
    protected void processConsent(OAuth2AuthzMessageContext messageContext) throws OAuth2Exception {

        String consent = messageContext.getRequest().getParameterValue(OAuth2.CONSENT);
        String spName = ((ServiceProvider)messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER)).getApplicationName();
        if (StringUtils.isNotBlank(consent)) {
            if(StringUtils.equals("ApproveAlways", consent)) {
                OAuth2ConsentStore.getInstance().approveAppAlways(messageContext.getAuthzUser(), spName, true);
            } else {

            }
        } else if(StringUtils.equals("Deny", consent)) {
            OAuth2ConsentStore.getInstance().approveAppAlways(messageContext.getAuthzUser(), spName, false);
            throw OAuth2ConsentException.error("User denied the request");
        } else {
            throw OAuth2InternalException.error("Cannot find consent parameter");
        }
    }

    /**
     * Issues the authorization endpoint response
     *
     * @param messageContext The runtime message context
     * @return OAuth2 authorization endpoint response
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException Exception occurred while issuing authorization endpoint response
     */
    protected abstract InboundAuthenticationResponse.InboundAuthenticationResponseBuilder getAuthzResponseBuilder(
            OAuth2AuthzMessageContext messageContext) throws OAuth2RuntimeException;
}
