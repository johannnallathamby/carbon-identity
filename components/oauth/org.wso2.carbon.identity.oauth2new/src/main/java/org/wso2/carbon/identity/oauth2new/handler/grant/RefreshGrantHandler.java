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

package org.wso2.carbon.identity.oauth2new.handler.grant;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth2new.OAuth2;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2TokenMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.RefreshGrantRequest;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.handler.HandlerManager;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;

public class RefreshGrantHandler extends AuthorizationGrantHandler {

    public void validateGrant(OAuth2TokenMessageContext messageContext) throws OAuth2Exception {

        String refreshToken = ((RefreshGrantRequest)messageContext.getRequest()).getRefreshToken();

        OAuth2DAO dao = HandlerManager.getInstance().getOAuth2DAO(messageContext);

        AccessToken accessToken = dao.getLatestAccessTokenByRefreshToken(refreshToken, messageContext);

        if(StringUtils.equals(accessToken.getClientId(), messageContext.getClientId())) {
            throw OAuth2ClientException.error("Unauthorized client trying to refresh token");
        }

        if (!OAuth2.TokenState.ACTIVE.equals(accessToken.getRefreshToken()) &&
                !OAuth2.TokenState.EXPIRED.equals(accessToken.getAccessTokenState())) {
            throw OAuth2ClientException.error("Invalid refresh token");
        }

        messageContext.setAuthzUser(accessToken.getAuthzUser());
        messageContext.setApprovedScopes(accessToken.getScopes());
        messageContext.addParameter(OAuth2.PREV_ACCESS_TOKEN, accessToken);
    }
}
