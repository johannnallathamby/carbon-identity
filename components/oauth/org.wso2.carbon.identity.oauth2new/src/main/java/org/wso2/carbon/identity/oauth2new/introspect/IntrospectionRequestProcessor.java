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

package org.wso2.carbon.identity.oauth2new.introspect;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.AuthenticationFrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.common.ClientType;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2InboundRequestProcessor;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;

public class IntrospectionRequestProcessor extends OAuth2InboundRequestProcessor {

    @Override
    public String getName() {
        return "IntrospectionRequestProcessor";
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
        if(StringUtils.isNotBlank(authenticationRequest.getParameterValue("token"))) {
            return true;
        }
        return false;
    }

    @Override
    public InboundAuthenticationResponse process(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {

        IntrospectionRequest introspectionRequest = (IntrospectionRequest)authenticationRequest;
        IntrospectionMessageContext messageContext = new IntrospectionMessageContext(introspectionRequest,
                new HashMap<String,String>());

        if(ClientType.CONFIDENTIAL == clientType(messageContext)) {
            String clientId = authenticateClient(messageContext);
            messageContext.setClientId(clientId);
        }


        IntrospectionResponseBuilder introspectionResponseBuilder = introspect(messageContext);
        InboundAuthenticationResponse.InboundAuthenticationResponseBuilder builder = getIntrospectionResponseBuilder(
                introspectionResponseBuilder, messageContext);
        return builder.build();

    }

    protected IntrospectionResponseBuilder introspect(IntrospectionMessageContext messageContext) throws OAuth2Exception {
        IntrospectionHandler handler = HandlerManager.getInstance().getIntrospectionHandler(messageContext);
        return handler.introspect(messageContext);
    }

    protected InboundAuthenticationResponse.InboundAuthenticationResponseBuilder getIntrospectionResponseBuilder
            (IntrospectionResponseBuilder builder, IntrospectionMessageContext messageContext) {

        InboundAuthenticationResponse.InboundAuthenticationResponseBuilder responseBuilder = new
                InboundAuthenticationResponse.InboundAuthenticationResponseBuilder();
        responseBuilder.setStatusCode(HttpServletResponse.SC_OK);
        responseBuilder.setBody(builder.build());
        responseBuilder.addHeader(OAuth2.Header.CACHE_CONTROL, OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
        responseBuilder.addHeader(OAuth2.Header.PRAGMA, OAuth2.HeaderValue.PRAGMA_NO_CACHE);
        return responseBuilder;
    }

    /**
     * Finds out the client type
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception
     */
    protected ClientType clientType(IntrospectionMessageContext messageContext) {
        return HandlerManager.getInstance().clientType(messageContext);
    }

    /**
     * Authenticates confidential clients
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the client was confidential and was authenticated successfully
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception
     */
    protected String authenticateClient(IntrospectionMessageContext messageContext) throws OAuth2Exception {
        return HandlerManager.getInstance().authenticateClient(messageContext);
    }
}
