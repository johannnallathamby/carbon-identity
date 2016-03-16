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

package org.wso2.carbon.identity.application.authentication.framework.inbound;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthenticatedRequestFactory extends InboundAuthenticationRequestFactory {

    @Override
    public String getName() {
        return "AuthenticatedRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationFrameworkRuntimeException {

        if(StringUtils.isNotBlank(request.getParameter(InboundAuthenticationConstants.RequestProcessor.SESSION_DATA_KEY))){
            return true;
        }
        return false;
    }

    @Override
    public AuthenticatedRequest create(HttpServletRequest request, HttpServletResponse response) throws
            AuthenticationFrameworkRuntimeException {

        AuthenticatedRequest.AuthenticatedRequestBuilder builder =
                new AuthenticatedRequest.AuthenticatedRequestBuilder(request, response);
        builder.setSessionDataKey(request.getParameter(InboundAuthenticationConstants.RequestProcessor
                .SESSION_DATA_KEY));
        return builder.build();
    }
}
