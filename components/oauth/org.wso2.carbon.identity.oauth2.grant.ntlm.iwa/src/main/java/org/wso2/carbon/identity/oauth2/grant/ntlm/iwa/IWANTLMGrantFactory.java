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

package org.wso2.carbon.identity.oauth2.grant.ntlm.iwa;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.oauth2new.bean.message.token.TokenRequestFactory;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IWANTLMGrantFactory extends TokenRequestFactory {

    @Override
    public String getName() {
        return "IWANTLMGrantFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws FrameworkRuntimeException {
        if(StringUtils.equals(IWANTLMConstants.IWA_NTLM_GRANT_TYPE, request.getParameter(OAuth.OAUTH_GRANT_TYPE))) {
            return true;
        }
        return false;
    }

    @Override
    public IWANTLMGrantRequest create(HttpServletRequest request, HttpServletResponse response) throws
            FrameworkRuntimeException {

        IWANTLMGrantRequest.IWANTLMGrantBuilder builder = new IWANTLMGrantRequest.IWANTLMGrantBuilder
                (request, response);
        builder.setWindowsToken(request.getParameter(IWANTLMConstants.WINDOWS_TOKEN));
        builder.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));
        return builder.build();
    }
}
