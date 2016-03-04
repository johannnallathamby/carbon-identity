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

package org.wso2.carbon.identity.oauth2new.admin.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.AbstractIdentityUserOperationEventListener;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2new.admin.dao.OAuth2AdminDAO;
import org.wso2.carbon.identity.oauth2new.dao.CacheBackedOAuth2DAO;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Map;
import java.util.Set;

/**
 * Hook to update OAuth2 data for user events
 */
public class OAuth2UserOperationEventListener extends AbstractIdentityUserOperationEventListener {

    private static final Log log = LogFactory.getLog(OAuth2UserOperationEventListener.class);

    /**
     * Bundle execution order id.
     */
    @Override
    public int getExecutionOrderId() {
        int orderId = getOrderId();
        if (orderId != IdentityCoreConstants.EVENT_LISTENER_ORDER_ID) {
            return orderId;
        }
        return 60;
    }

    /**
     * Deleting user from the identity database prerequisites.
     */
    @Override
    public boolean doPreDeleteUser(String username, UserStoreManager userStoreManager) throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return revokeTokensForDeletedUser(username, userStoreManager);

    }

    @Override
    public boolean doPostSetUserClaimValues(String userName, Map<String, String> claims, String profileName,
                                            UserStoreManager userStoreManager) {

        if (!isEnable()) {
            return true;
        }
        return revokeTokensOfLockedUser(userName, userStoreManager);
    }

    @Override
    public boolean doPostAuthenticate(String userName, boolean authenticated, UserStoreManager userStoreManager)
            throws UserStoreException {

        if (!isEnable()) {
            return true;
        }
        return revokeTokensOfLockedUser(userName, userStoreManager);
    }

    private boolean revokeTokensOfLockedUser(String userName, UserStoreManager userStoreManager){

        IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();

        if (errorContext != null && errorContext.getErrorCode() == UserCoreConstants.ErrorCode.USER_IS_LOCKED){
            return revokeTokensForDeletedUser(userName, userStoreManager);
        }
        return true;
    }

    private boolean revokeTokensForDeletedUser(String username, UserStoreManager userStoreManager){

        OAuth2AdminDAO dao = OAuth2AdminDAO.getInstance();
        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(username);

        Set<String> clientIds = null;
        try {
            // get all the distinct client Ids authorized by this user
            clientIds = dao.getAllTimeAuthorizedClientIds(authenticatedUser);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while retrieving apps authorized by User ID : " + authenticatedUser, e);
            return true;
        }
        for (String clientId : clientIds) {
            Set<AccessTokenDO> accessTokenDOs = null;
            try {
                // retrieve all ACTIVE or EXPIRED access tokens for particular client authorized by this user
                accessTokenDOs = tokenMgtDAO.retrieveAccessTokens(clientId, authenticatedUser, userStoreDomain, true);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while retrieving access tokens issued for " +
                        "Client ID : " + clientId + ", User ID : " + authenticatedUser;
                log.error(errorMsg, e);
                return true;
            }
            for (AccessTokenDO accessTokenDO : accessTokenDOs) {
                //Clear cache
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                        OAuth2Util.buildScopeString(accessTokenDO.getScope()));
                OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
                OAuthUtil.clearOAuthCache(accessTokenDO.getAccessToken());
                AccessTokenDO scopedToken = null;
                try {
                    // retrieve latest access token for particular client, user and scope combination if its ACTIVE or EXPIRED
                    scopedToken = tokenMgtDAO.retrieveLatestAccessToken(
                            clientId, authenticatedUser, userStoreDomain,
                            OAuth2Util.buildScopeString(accessTokenDO.getScope()), true);
                } catch (IdentityOAuth2Exception e) {
                    String errorMsg = "Error occurred while retrieving latest " +
                            "access token issued for Client ID : " +
                            clientId + ", User ID : " + authenticatedUser + " and Scope : " +
                            OAuth2Util.buildScopeString(accessTokenDO.getScope());
                    log.error(errorMsg, e);
                    return true;
                }
                if (scopedToken != null) {
                    try {
                        //Revoking token from database
                        tokenMgtDAO.revokeTokens(new String[]{scopedToken.getAccessToken()});
                    } catch (IdentityOAuth2Exception e) {
                        String errorMsg = "Error occurred while revoking " +
                                "Access Token : " + scopedToken.getAccessToken();
                        log.error(errorMsg, e);
                        return true;
                    }
                }
            }
        }
        return true;
    }
}
