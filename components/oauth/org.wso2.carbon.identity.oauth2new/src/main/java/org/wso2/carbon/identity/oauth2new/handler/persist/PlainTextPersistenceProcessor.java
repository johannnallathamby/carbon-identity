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

package org.wso2.carbon.identity.oauth2new.handler.persist;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;

/**
 * <Code>PlainTextPersistenceProcessor</Code> stores keys and secrets
 * in plain text in the database.
 */

public class PlainTextPersistenceProcessor extends TokenPersistenceProcessor {

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {
        return false;
    }

    @Override
    public String getProcessedClientId(Object token) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getPreprocessedClientId(Object processedToken) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedClientSecret(Object token) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getPreprocessedClientSecret(Object processedToken) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedAuthzCode(Object token) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getPreprocessedAuthzCode(Object processedToken) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedAccessToken(Object token) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getPreprocessedAccessToken(Object processedToken) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getProcessedRefreshToken(Object token) throws OAuth2Exception {
        return null;
    }

    @Override
    public String getPreprocessedRefreshToken(Object processedToken) throws OAuth2Exception {
        return null;
    }
}
