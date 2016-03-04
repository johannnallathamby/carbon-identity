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

package org.wso2.carbon.identity.oauth2new.bean.message.request.processor.authz;

import org.wso2.carbon.identity.oauth2new.bean.context.OAuth2AuthzMessageContext;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2AuthzResponse;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2Exception;
import org.wso2.carbon.identity.oauth2new.processor.request.OAuth2InboundRequestProcessor;

public abstract class AuthzRequestProcessor extends OAuth2InboundRequestProcessor {

    protected boolean authorizeAccessDelegation(OAuth2AuthzMessageContext messageContext) throws
            OAuth2Exception {
        return true;
    }

    protected boolean validateScope(OAuth2AuthzMessageContext messageContext)
            throws OAuth2Exception {
        return true;
    }

    protected abstract OAuth2AuthzResponse issue(OAuth2AuthzMessageContext messageContext) throws OAuth2Exception;

}
