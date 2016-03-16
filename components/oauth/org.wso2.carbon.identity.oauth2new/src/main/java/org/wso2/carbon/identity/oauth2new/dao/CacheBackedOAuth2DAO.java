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

package org.wso2.carbon.identity.oauth2new.dao;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2new.model.AccessToken;
import org.wso2.carbon.identity.oauth2new.model.AuthzCode;

import java.sql.Connection;
import java.util.Set;

/*
 * Wraps a given OAuth2DAO object and provides caching feature for it
 */
public class CacheBackedOAuth2DAO extends OAuth2DAO {

    private OAuth2DAO wrappedDAO;

    public CacheBackedOAuth2DAO(OAuth2DAO dao) {
        this.wrappedDAO = dao;
    }

    @Override
    public AccessToken getLatestActiveOrExpiredAccessToken(String consumerKey, AuthenticatedUser authzUser, Set<String> scopes, OAuth2MessageContext messageContext) {
        return null;
    }

    @Override
    public void storeAccessToken(AccessToken newAccessToken, String oldAccessTokenId, String tokenState, String authzCodeId, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {

    }

    @Override
    protected void storeAccessToken(Connection connection, AccessToken newAccessToken, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {

    }

    @Override
    public void updateAccessTokenState(Set<String> accessTokenIds, String tokenState, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {

    }

    @Override
    protected void updateAccessTokenState(Connection connection, String tokenId, String tokenState, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {

    }

    @Override
    public AccessToken getLatestAccessTokenByRefreshToken(char[] refreshToken, OAuth2MessageContext messageContext)
            throws OAuth2RuntimeException {
        return null;
    }

    @Override
    public void storeAuthzCode(AuthzCode authzCode, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {

    }

    @Override
    public AuthzCode getAuthzCode(String authzCode, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {
        return null;
    }

    @Override
    public void updateAuthzCodeState(String authzCode, String state, OAuth2MessageContext messageContext) throws
            OAuth2RuntimeException {

    }

    @Override
    protected void updateAuthzCodeState(Connection connection, String authzCode, String state, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {

    }

    @Override
    protected void updateTokenIdForAuthzCodeId(Connection connection, String oldAccessTokenId, String newAccessTokenId, OAuth2MessageContext messageContext) throws OAuth2RuntimeException {

    }
}
