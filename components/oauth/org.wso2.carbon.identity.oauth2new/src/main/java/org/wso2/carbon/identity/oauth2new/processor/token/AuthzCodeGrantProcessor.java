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

package org.wso2.carbon.identity.oauth2new.processor.token;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.AuthzCodeGrantRequest;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.model.AuthzCode;
import org.wso2.carbon.identity.oauth2new.model.OAuth2ServerConfig;

/*
 * InboundRequestProcessor for grant_type=authz_code
 */
public class AuthzCodeGrantProcessor extends TokenProcessor {

    private static Log log = LogFactory.getLog(AuthzCodeGrantProcessor.class);

    @Override
    public String getName() {
        return "AuthzCodeGrantProcessor";
    }

    @Override
    public boolean canHandle(InboundAuthenticationRequest authenticationRequest) throws FrameworkException {
        return false;
    }

    @Override
    protected void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {

        String authorizationCode = ((AuthzCodeGrantRequest)messageContext.getRequest()).getCode();
        String redirectURI = ((AuthzCodeGrantRequest)messageContext.getRequest()).getRedirectURI();
        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);
        AuthzCode authzCode = dao.getAuthzCode(authorizationCode, messageContext);
        if (authzCode == null || !OAuth2.TokenState.ACTIVE.equals(authzCode.getCodeState())) {
            throw OAuth2ClientException.error("Invalid authorization code");
        }

        // Validate redirect_uri if it was presented in authorization request
        if (StringUtils.isNotBlank(authzCode.getRedirectURI())) {
            if(StringUtils.equals(authzCode.getRedirectURI(), redirectURI)) {
                throw OAuth2ClientException.error("Invalid redirect_uri");
            }
        }

        // Check whether the grant is expired
        long issuedTimeInMillis = authzCode.getIssuedTime().getTime();
        long validityPeriodInMillis = authzCode.getValidityPeriod();
        long timestampSkew = OAuth2ServerConfig.getInstance().getTimeStampSkew() * 1000;
        long currentTimeInMillis = System.currentTimeMillis();

        if ((currentTimeInMillis + timestampSkew) > (issuedTimeInMillis + validityPeriodInMillis)) {
            dao.updateAuthzCodeState(authorizationCode, OAuth2.TokenState.EXPIRED, messageContext);
            throw OAuth2ClientException.error("Authorization code expired");
        }

        messageContext.setAuthzUser(messageContext.getAuthzUser());
        messageContext.setApprovedScopes(authzCode.getScopes());
        messageContext.addParameter(OAuth2.AUTHZ_CODE, authzCode);
    }

}
