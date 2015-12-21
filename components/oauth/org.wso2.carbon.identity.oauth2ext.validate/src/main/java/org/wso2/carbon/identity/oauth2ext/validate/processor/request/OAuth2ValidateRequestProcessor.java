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

package org.wso2.carbon.identity.oauth2ext.validate.processor.request;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.oauth2ext.validate.context.OAuth2ValidationMessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.processor.request.OAuth2InboundRequestProcessor;

/**
 * OAuth access token validators should extend this class.
 * OAuth access token validator implementations can be plugged
 * to the system through the Identity configurations
 */
public abstract class OAuth2ValidateRequestProcessor extends OAuth2InboundRequestProcessor {

    public abstract InboundAuthenticationResponse process(InboundAuthenticationRequest authenticationRequest)
            throws FrameworkException;

    public abstract String getName();

    public abstract String getCallbackPath(InboundAuthenticationContext context) throws FrameworkException;

    public abstract String getRelyingPartyId();

    public abstract int getPriority();

    public abstract boolean canHandle(InboundAuthenticationRequest authenticationRequest) throws FrameworkException;

    /**
     * Validate whether the claimed user is the rightful resource owner
     * @param messageContext <code>ValidationMessageContext</code>
     * @return <Code>true</Code>|<Code>false</Code> if it's the rightful resource owner
     * @throws OAuth2Exception Error when authorizing access delegation
     */
    protected boolean validateAccessDelegation(OAuth2ValidationMessageContext messageContext) throws OAuth2Exception {
        return true;
    }

    /**
     * Validate whether scope requested by the access token is valid
     * @param messageContext <code>ValidationMessageContext</code>
     * @return <Code>true</Code>|<Code>false</Code> if the scope is correct
     * @throws OAuth2Exception Error when validating scope
     */
    protected boolean validateScope(OAuth2ValidationMessageContext messageContext) throws OAuth2Exception {
        return true;
    }

    /**
     * For validation of token profile specific items.
     * E.g. validation of HMAC signature in HMAC token profile
     */
    protected boolean validateAccessToken(OAuth2ValidationMessageContext validationReqDTO) throws OAuth2Exception {
        return true;
    }
}
