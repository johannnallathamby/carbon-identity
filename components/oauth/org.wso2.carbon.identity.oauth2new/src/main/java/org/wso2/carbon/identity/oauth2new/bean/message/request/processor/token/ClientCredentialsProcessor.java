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

package org.wso2.carbon.identity.oauth2new.bean.message.request.processor.token;


import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;

/**
 * Grant Handler for Grant Type : client_credentials
 */
public class ClientCredentialsProcessor extends TokenRequestProcessor {


    @Override
    public boolean validateGrant(OAuth2TokenMessageContext messageContext) {
        return true;
    }

    @Override
    protected OAuth2TokenResponse issue(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return null;
    }

    @Override
    public InboundAuthenticationResponse process(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {
        return null;
    }

    @Override
    public String getName() {
        return null;
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
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {
        return false;
    }
}
