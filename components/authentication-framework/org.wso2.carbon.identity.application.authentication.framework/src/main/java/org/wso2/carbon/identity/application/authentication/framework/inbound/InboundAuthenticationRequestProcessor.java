/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authentication.framework.inbound;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.Properties;

public abstract class InboundAuthenticationRequestProcessor {

    protected Properties properties = new Properties();

    /**
     * Process inbound authentication request
     *
     * @param properties Inbound authenticator properties
     *
     * @throws FrameworkException
     */
    public void init(Properties properties) throws FrameworkException {
        if(properties != null){
            this.properties = properties;
        }
    }

    /**
     * Process inbound authentication request
     *
     * @param authenticationRequest Inbound authentication request
     * @return Inbound authentication response
     * @throws FrameworkException
     */
    public abstract InboundAuthenticationResponse process(InboundAuthenticationRequest authenticationRequest)
            throws FrameworkException;

    /**
     * Get Name
     * @return Name
     */
    public abstract String getName();

    /**
     * Get callback path
     *
     * @param context Inbound authentication context
     * @return Callback path
     * @throws FrameworkException
     */
    public abstract String getCallbackPath(InboundAuthenticationContext context) throws AuthenticationFrameworkRuntimeException;

    /**
     * Get relying party id
     * @return Relying party id
     */
    public abstract String getRelyingPartyId();

    /**
     * Get Priority
     * @return Priority
     */
    public abstract int getPriority();

    /**
     * Can handle
     * @param authenticationRequest Inbound authentication request
     * @return boolean
     * @throws FrameworkException
     */
    public abstract boolean canHandle(InboundAuthenticationRequest authenticationRequest) throws FrameworkException;

    /**
     * Build response for framework login
     *
     * @param context Inbound authentication context
     * @return
     * @throws IOException
     * @throws FrameworkException
     */
    protected InboundAuthenticationResponse.InboundAuthenticationResponseBuilder getBuilderForFrameworkLogin(
            InboundAuthenticationContext context) throws AuthenticationFrameworkRuntimeException {

        String sessionDataKey = UUIDGenerator.generateUUID();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        InboundAuthenticationRequest inboundAuthenticationRequest = context.getRequest();

        Map<String, String[]> parameterMap = inboundAuthenticationRequest.getParameters();

        parameterMap.put(FrameworkConstants.SESSION_DATA_KEY, new String[] { sessionDataKey });
        parameterMap.put(FrameworkConstants.RequestParams.TYPE, new String[] { getName() });

        authenticationRequest.appendRequestQueryParams(parameterMap);

        for (Object entry : inboundAuthenticationRequest.getHeaders().keySet()) {
            authenticationRequest.addHeader(((Map.Entry<String,String>)entry).getKey(),
                    ((Map.Entry<String, String>)entry).getValue());
        }

        authenticationRequest.setRelyingParty(getRelyingPartyId());
        authenticationRequest.setType(getName());
        authenticationRequest.setPassiveAuth((Boolean)context.getParameter(InboundAuthenticationConstants.PassiveAuth));
        authenticationRequest.setForceAuth((Boolean)context.getParameter(InboundAuthenticationConstants.ForceAuth));
        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(getCallbackPath(context), "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw AuthenticationFrameworkRuntimeException.error(e.getMessage(), e);
        }

        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);

        InboundAuthenticationContextCacheEntry contextCacheEntry = new InboundAuthenticationContextCacheEntry(context);
        InboundAuthenticationUtil.addInboundAuthenticationContextToCache(sessionDataKey, contextCacheEntry);

        InboundAuthenticationResponse.InboundAuthenticationResponseBuilder responseBuilder =
                new InboundAuthenticationResponse.InboundAuthenticationResponseBuilder();
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.AUTH_NAME,
                new String[]{getName()});
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.SESSION_DATA_KEY,
                new String[]{sessionDataKey});
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.CALL_BACK_PATH,
                new String[]{getCallbackPath(context)});
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.RELYING_PARTY,
                new String[]{getRelyingPartyId()});
        //type parameter is using since framework checking it, but future it'll use AUTH_NAME
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.AUTH_TYPE,
                new String[]{getName()});
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }

    /**
     * Build response for framework logout
     *
     * @param context Inbound authentication context
     * @return
     * @throws IOException
     * @throws IdentityApplicationManagementException
     * @throws FrameworkException
     */
    protected InboundAuthenticationResponse.InboundAuthenticationResponseBuilder getBuilderForFrameworkLogout(
            InboundAuthenticationContext context) throws AuthenticationFrameworkRuntimeException {

        String sessionDataKey = UUIDGenerator.generateUUID();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        InboundAuthenticationRequest inboundAuthenticationRequest = context.getRequest();

        Map<String, String[]> parameterMap = inboundAuthenticationRequest.getParameters();

        parameterMap.put(FrameworkConstants.SESSION_DATA_KEY, new String[] { sessionDataKey });
        parameterMap.put(FrameworkConstants.RequestParams.TYPE, new String[] { getName() });

        authenticationRequest.appendRequestQueryParams(parameterMap);

        for (Object entry : inboundAuthenticationRequest.getHeaders().keySet()) {
            authenticationRequest.addHeader(((Map.Entry<String,String>)entry).getKey(),
                    ((Map.Entry<String, String>)entry).getValue());
        }

        authenticationRequest.setRelyingParty(getRelyingPartyId());
        authenticationRequest.setType(getName());
        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(getCallbackPath(context), "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw AuthenticationFrameworkRuntimeException.error(e.getMessage(), e);
        }
        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT,
                new String[]{"true"});

        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);

        InboundAuthenticationContextCacheEntry contextCacheEntry = new InboundAuthenticationContextCacheEntry(context);
        InboundAuthenticationUtil.addInboundAuthenticationContextToCache(sessionDataKey, contextCacheEntry);

        InboundAuthenticationResponse.InboundAuthenticationResponseBuilder responseBuilder =
                new InboundAuthenticationResponse.InboundAuthenticationResponseBuilder();
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.AUTH_NAME, new String[]{getName()});
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.SESSION_DATA_KEY, new String[]{sessionDataKey});
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.CALL_BACK_PATH,
                new String[]{getCallbackPath(context)});
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.RELYING_PARTY,
                new String[]{getRelyingPartyId()});
        //type parameter is using since framework checking it, but future it'll use AUTH_NAME
        responseBuilder.addParameter(InboundAuthenticationConstants.RequestProcessor.AUTH_TYPE, new String[]{getName()});
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }

    protected boolean isContextAvailable(InboundAuthenticationRequest request) {
        String sessionDataKey = request.getParameterValue(InboundAuthenticationConstants.RequestProcessor
                .SESSION_DATA_KEY);
        if(StringUtils.isNotBlank(sessionDataKey)){
            InboundAuthenticationContextCacheEntry entry = InboundAuthenticationContextCache.getInstance()
                    .getValueFromCache(new InboundAuthenticationContextCacheKey(sessionDataKey));
            if(entry != null){
                return true;
            }
        }
        return false;
    }

    protected InboundAuthenticationContext getContextIfAvailable(InboundAuthenticationRequest request) {
        String sessionDataKey = request.getParameterValue(InboundAuthenticationConstants.RequestProcessor
                .SESSION_DATA_KEY);
        if(StringUtils.isNotBlank(sessionDataKey)){
            InboundAuthenticationContextCacheEntry entry = InboundAuthenticationContextCache.getInstance()
                    .getValueFromCache(new InboundAuthenticationContextCacheKey(sessionDataKey));
            if(entry != null){
                return entry.getInboundAuthenticationContext();
            }
        }
        return null;
    }

    protected AuthenticationResult processResponseFromFrameworkLogin(InboundAuthenticationContext context) {

        String sessionDataKey = context.getRequest().getParameterValue(InboundAuthenticationConstants.RequestProcessor
                .SESSION_DATA_KEY);
        AuthenticationResultCacheEntry entry = FrameworkUtils.getAuthenticationResultFromCache(sessionDataKey);
        AuthenticationResult authnResult = null;
        if(entry != null) {
            authnResult = entry.getResult();
        } else {
            throw AuthenticationFrameworkRuntimeException.error("Cannot find AuthenticationResult from the cache");
        }
        FrameworkUtils.removeAuthenticationResultFromCache(sessionDataKey);
        if (authnResult.isAuthenticated()) {
            context.addParameter(InboundAuthenticationConstants.RequestProcessor.AUTHENTICATION_RESULT, authnResult);
        }
        return authnResult;
    }
}
