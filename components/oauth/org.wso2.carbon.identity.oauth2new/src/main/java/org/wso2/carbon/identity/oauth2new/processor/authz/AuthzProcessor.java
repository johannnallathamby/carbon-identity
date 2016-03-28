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

import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundResponse;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.authz.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2InboundRequestProcessor;

import java.util.HashMap;

/*
 * InboundRequestProcessor for OAuth2 Authorization Endpoint
 */
public class AuthzProcessor extends OAuth2InboundRequestProcessor {

    @Override
    public String getName() {
        return "AuthzProcessor";
    }

    public int getPriority() {
        return 0;
    }

    public String getCallbackPath(InboundMessageContext context) {
        return null;
    }

    public String getRelyingPartyId() {
        return null;
    }

    public boolean canHandle(InboundRequest inboundRequest) {
        if(inboundRequest.getParameter(OAuth.OAUTH_RESPONSE_TYPE) != null) {
            return true;
        }
        return false;
    }

    public InboundResponse process(InboundRequest inboundRequest) throws FrameworkException {

        OAuth2AuthzMessageContext messageContext = new OAuth2AuthzMessageContext(
                (OAuth2AuthzRequest) inboundRequest, new HashMap<String,String>());

        validateClient(messageContext);

        return initializeResourceOwnerAuthentication(messageContext);
    }

    protected void validateClient(OAuth2AuthzMessageContext messageContext) throws OAuth2ClientException {

        String clientId = messageContext.getRequest().getClientId();

        ServiceProvider serviceProvider = null;
        // Validate clientId, redirect_uri, response_type allowed
        messageContext.addParameter(OAuth2.OAUTH2_SERVICE_PROVIDER, serviceProvider);
    }

    protected InboundResponse initializeResourceOwnerAuthentication(OAuth2AuthzMessageContext messageContext) {
        return buildResponseForFrameworkLogin(messageContext).build();
    }

}