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

import org.wso2.carbon.identity.core.handler.HandlerComparable;
import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2MessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2Response;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;

import java.util.Properties;

public abstract class ResponseIssuer implements HandlerComparable {

    protected Properties properties = new Properties();

    public void init(Properties properties) {
        if(properties != null){
            this.properties = properties;
        }
    }

    public abstract boolean canIssue(OAuth2MessageContext messageContext) throws OAuth2Exception;

    /**
     * Tells if refresh tokens must be issued or not.
     *
     * @return <Code>true</Code>|<Code>false</Code> if refresh tokens must be issued or not
     */
    protected abstract  boolean issueRefreshToken(OAuth2MessageContext messageContext) throws OAuth2Exception;

    public abstract OAuth2Response issue(OAuth2MessageContext messageContext) throws OAuth2Exception;

}
