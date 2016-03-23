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

package org.wso2.carbon.identity.oidc.processor;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundResponse;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2InboundRequestProcessor;
import org.wso2.carbon.identity.oidc.bean.context.UserInfoMessageContext;
import org.wso2.carbon.identity.oidc.bean.message.userinfo.UserInfoRequest;

import java.util.HashMap;

public class UserInfoProcessor extends OAuth2InboundRequestProcessor  {

    @Override
    public String getName() {
        return "UserInfoProcessor";
    }

    @Override
    public String getCallbackPath(InboundMessageContext context) throws FrameworkRuntimeException {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean canHandle(InboundRequest inboundRequest) throws FrameworkException {
        return false;
    }

    @Override
    public InboundResponse process(InboundRequest inboundRequest) throws FrameworkException {

        UserInfoMessageContext messageContext = new UserInfoMessageContext((UserInfoRequest) inboundRequest,
                new HashMap<String,String>());

        return null;
    }
}
