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

package org.wso2.carbon.identity.oauth2new.handler.persist;

import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;

/**
 * To process OAuth2 tokens just before storing them in the database.
 * E.g. to encrypt tokens before storing them in the database.
 */
public abstract class TokenPersistenceProcessor extends AbstractIdentityHandler {

    public abstract String getProcessedClientId(String clientId) throws OAuth2RuntimeException;

    public abstract String getPreprocessedClientId(String processedClientId) throws OAuth2RuntimeException;

    public abstract String getProcessedClientSecret(String clientSecret) throws OAuth2RuntimeException;

    public abstract String getPreprocessedClientSecret(String processedClientSecret) throws OAuth2RuntimeException;

    public abstract String getProcessedAuthzCode(String authzCode) throws OAuth2RuntimeException;

    public abstract String getPreprocessedAuthzCode(String processedAuthzCode) throws OAuth2RuntimeException;

    public abstract String getProcessedAccessToken(String accessToken) throws OAuth2RuntimeException;

    public abstract String getPreprocessedAccessToken(String processedAccessToken) throws OAuth2RuntimeException;

    public abstract String getProcessedRefreshToken(String refreshToken) throws OAuth2RuntimeException;

    public abstract String getPreprocessedRefreshToken(String processedRefreshToken) throws OAuth2RuntimeException;

}
