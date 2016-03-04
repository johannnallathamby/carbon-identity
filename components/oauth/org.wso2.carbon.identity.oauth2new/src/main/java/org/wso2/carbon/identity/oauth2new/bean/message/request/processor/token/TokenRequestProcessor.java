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


import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.processor.request.OAuth2InboundRequestProcessor;

public abstract class TokenRequestProcessor extends OAuth2InboundRequestProcessor {

    /**
     * Validate the Authorization Grant
     * @param messageContext <code>TokenMessageContext</code>
     * @return <Code>true</Code>|<Code>false</Code> if the grant_type is valid or not
     *         the authorization grant.
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception Error when validating grant
     */
    public boolean validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return true;
    }

    /**
     * Validate whether the claimed user is the rightful resource owner
     * @param messageContext <code>TokenMessageContext</code>
     * @return <Code>true</Code>|<Code>false</Code> if it's the rightful resource owner
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception Error when authorizing access delegation
     */
    protected boolean authorizeAccessDelegation(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return true;
    }

    /**
     * Validate whether scope requested by the access token is valid
     * @param messageContext <code>TokenMessageContext</code>
     * @return <Code>true</Code>|<Code>false</Code> if the scope is correct
     * @throws org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception Error when validating scope
     */
    protected boolean validateScope(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return true;
    }

    protected abstract OAuth2TokenResponse issue(OAuth2TokenMessageContext messageContext) throws OAuth2Exception;

}
