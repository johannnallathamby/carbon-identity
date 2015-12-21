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

package org.wso2.carbon.identity.oauth2new.handler.issuer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2AuthzResponse;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2Response;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;

import java.util.Set;

// Try to implement this in a way it does not have different implementations for Authorization endpoint and token
// endpoint. If you can't extend this class and handle authz endpoint and token endpoint as two extensions
public class BearerTokenResponseIssuer extends ResponseIssuer {

    private static Log log = LogFactory.getLog(BearerTokenResponseIssuer.class);

    public boolean canIssue(OAuth2MessageContext messageContext) throws OAuth2Exception {
        return true;
    }

    @Override
    protected boolean issueRefreshToken(OAuth2MessageContext messageContext) throws OAuth2Exception {
        return false;
    }

    @Override
    public OAuth2Response issue(OAuth2MessageContext messageContext) throws OAuth2Exception {
        return null;
    }

    protected OAuth2AuthzResponse issueAuthzResponse(OAuth2AuthzMessageContext messageContext) throws OAuth2Exception {
        return null;
    }

    protected OAuth2TokenResponse issueTokenResponse(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {
        return null;
    }

    protected AccessToken doesValidTokenExist(String clientId, User authzUser, Set<String> approvedScopes,
                                                     MessageContext messageContext) throws OAuth2Exception {
        return null;
    }

    protected AccessToken issueNewToken(String clientId, String redirectURI, User authzUser, long callbackValidityPeriod,
                                        Set<String> approvedScopes, String tokenUserType, MessageContext messageContext)
            throws OAuth2Exception {

        return null;
    }

    @Override
    public int getPriority(MessageContext messageContext) throws IdentityRuntimeException {
        return 0;
    }
}
