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

package org.wso2.carbon.identity.oauth2new.bean.message.processor.token;


import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.processor.InboundProcessor;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2TokenRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.HashMap;

/*
 * InboundRequestProcessor for OAuth2 Token Endpoint
 */
public abstract class TokenRequestProcessor extends InboundProcessor {

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

        validateGrant(messageContext);

        return issue(messageContext);

    }

    /**
     * Validates the Authorization Grant
     *
     * @param messageContext The runtime message context
     * @return {@code true} only if the authorization grant is valid
     * @throws OAuth2Exception Exception occurred while validating the grant
     */
    protected void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        /* Method not implemented */
    }

    /**
     * Issues the access token
     *
     * @param messageContext The runtime message context
     * @return OAuth2 access token response
     * @throws OAuth2Exception Exception occurred while issuing OAuth2 access token response
     */
    protected OAuth2TokenResponse issue(OAuth2TokenMessageContext messageContext) throws OAuth2RuntimeException {
        return null;
    }
}
