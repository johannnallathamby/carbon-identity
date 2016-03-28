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

package org.wso2.carbon.identity.oauth2new.bean.message;

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundRequestFactory;
import org.wso2.carbon.identity.oauth2new.bean.message.token.OAuth2TokenRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class OAuth2InboundRequestFactory extends InboundRequestFactory {

    @Override
    public String getName() {
        return "OAuth2InboundRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws FrameworkRuntimeException {
        if(StringUtils.isNotBlank(request.getParameter(OAuth.OAUTH_GRANT_TYPE)) ||
                StringUtils.isNotBlank(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE))) {
            return true;
        }
        return false;
    }

    public OAuth2InboundRequest create(HttpServletRequest request, HttpServletResponse response)
            throws FrameworkRuntimeException, FrameworkException {

        OAuth2TokenRequest.TokenRequestBuilder builder = new OAuth2TokenRequest.TokenRequestBuilder
                (request, response);
        builder.setGrantType(request.getParameter(OAuth.OAUTH_GRANT_TYPE));
        builder.setGrantType(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE));
        return builder.build();
    }

}