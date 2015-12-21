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

import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.util.HandlerComparable;

import java.util.Properties;

/**
 * <Code>TokenPersistenceProcessor</Code> implementations are used to
 * process keys and secrets just before storing them in the database.
 * E.g. to encrypt tokens before storing them in the database.
 * Implementations of this interface can be configured through
 * the identity.xml.
 */
public abstract class TokenPersistenceProcessor implements HandlerComparable {

    protected Properties properties = new Properties();

    public void init(Properties properties) {
        if(properties != null) {
            this.properties = properties;
        }
    }

    public abstract String getProcessedToken(String tokenTypeIdentifier, String token) throws OAuth2Exception;

    public abstract String getPreprocessedToken(String tokenTypeIdentifier, String processedToken) throws
            OAuth2Exception;

    @Override
    public int getPriority(OAuth2MessageContext messageContext) throws OAuth2Exception {
        return 0;
    }

}
