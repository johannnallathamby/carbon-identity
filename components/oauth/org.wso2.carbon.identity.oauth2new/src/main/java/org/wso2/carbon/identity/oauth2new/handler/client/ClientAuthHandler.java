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

package org.wso2.carbon.identity.oauth2new.handler.client;

import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.HandlerComparable;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.common.ClientType;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2RuntimeException;

import java.util.Properties;

public abstract class ClientAuthHandler extends IdentityHandler implements HandlerComparable {

    @Override
    public int getPriority(MessageContext messageContext) throws OAuth2RuntimeException {
        return 0;
    }

    /**
     * Tells if the clients are confidential or public.
     *
     * @return <Code>true</Code>|<Code>false</Code> if the client type is confidential or not.
     * @throws OAuth2Exception Error when finding client type
     */
    public abstract ClientType clientType(OAuth2MessageContext messageContext) throws OAuth2Exception;

    /**
     * Authenticates the OAuth 2.0 client
     *
     * @param messageContext <code>MessageContext</code>
     * @return Client Id if authentication was successful, <Code>null</Code> otherwise
     * @throws OAuth2Exception Error when authenticating client
     */
    public abstract String authenticate(OAuth2MessageContext messageContext) throws OAuth2Exception;

}
