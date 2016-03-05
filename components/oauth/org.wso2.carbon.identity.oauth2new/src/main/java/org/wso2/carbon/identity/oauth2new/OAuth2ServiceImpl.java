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

package org.wso2.carbon.identity.oauth2new;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2Request;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2TokenRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2AuthzResponse;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2TokenResponse;
import org.wso2.carbon.identity.oauth2new.dao.CacheBackedOAuth2DAO;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAOHandler;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;

import java.util.HashMap;
import java.util.Map;

public class OAuth2ServiceImpl implements OAuth2Service {

    private static Log log = LogFactory.getLog(OAuth2Service.class);

    private static volatile OAuth2Service instance = new OAuth2ServiceImpl();
    private Map<String,OAuth2DAO> cachedDAOMap = new HashMap<>();

    private OAuth2ServiceImpl() {

    }

    public static OAuth2Service getInstance() {
        return instance;
    }

    /**
     * Process the authorization request and issue an authorization code or access token depending
     * on the Response Type available in the request.
     *
     * @param request <code>OAuth2AuthorizeReqDTO</code> containing information about the authorization request.
     * @return <code>OAuth2AuthorizeRespDTO</code> instance containing the access token or authorization code.
     */
    public OAuth2AuthzResponse process(OAuth2AuthzRequest request) throws OAuth2Exception {

        return null;
    }

    /**
     * Issue access token in exchange to an Authorization Grant.
     *
     * @param request <Code>OAuth2AccessTokenReqDTO</Code> representing the Access Token request
     * @return <Code>OAuth2AccessTokenRespDTO</Code> representing the Access Token servletResponse
     * @throws OAuth2Exception Error when issuing access token
     */
    public OAuth2TokenResponse process(OAuth2TokenRequest request)
            throws OAuth2Exception {

        return null;
    }

    /**
     * Check Whether the provided client_id and the redirect_uri are valid.
     *
     * @param request <Code>OAuth2ClientValidationRequestDTO</Code>
     *                contains client_id and redirect_uri found in the request
     * @return <code>OAuth2ClientValidationResponseDTO</code> bean with validity information,
     *          application name and redirect URI
     * @throws OAuth2Exception Error when validating client info
     */
    private boolean validateClient(OAuth2Request request) throws OAuth2Exception {

        return false;
    }

    protected OAuth2DAO getOAuth2DAO(OAuth2MessageContext messageContext) {

        // Call Handler Manager and get the corresponding OAuth2DAOHandler first
        OAuth2DAOHandler daoHandler = null;

        //Wrap the OAuth2DAOHandler
        OAuth2DAO dao = cachedDAOMap.get(daoHandler.getName());
        if(dao == null){
            synchronized (OAuth2ServiceImpl.class) {
                if(dao == null) {
                    CacheBackedOAuth2DAO cachedDAO = new CacheBackedOAuth2DAO(dao);
                    cachedDAOMap.put(daoHandler.getName(), cachedDAO);
                    return cachedDAO;
                }
            }
        }
        return dao;
    }
}
