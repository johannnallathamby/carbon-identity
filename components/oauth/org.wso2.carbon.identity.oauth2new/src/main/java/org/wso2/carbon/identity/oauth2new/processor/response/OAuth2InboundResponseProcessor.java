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

package org.wso2.carbon.identity.oauth2new.processor.response;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationResponseProcessor;

public class OAuth2InboundResponseProcessor extends InboundAuthenticationResponseProcessor {


    @Override
    public InboundAuthenticationResponse processResponse(InboundAuthenticationContext context) throws FrameworkException {
        return null;
    }

    @Override
    public boolean canHandle(InboundAuthenticationContext context, InboundAuthenticationRequest request) throws FrameworkException {
        return false;
    }

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public boolean isDirectResponseRequired() {
        return false;
    }

    @Override
    public String getName() {
        return "OAuth2InboundResponseProcessor";
    }
}
