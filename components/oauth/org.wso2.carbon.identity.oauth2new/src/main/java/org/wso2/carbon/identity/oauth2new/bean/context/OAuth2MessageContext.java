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

package org.wso2.carbon.identity.oauth2new.bean.context;

import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2AuthzRequest;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2Request;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2AuthzResponse;
import org.wso2.carbon.identity.oauth2new.bean.message.response.OAuth2Response;

import java.io.Serializable;
import java.util.Map;

/*
 * Message context that holds information about the request to an endpoint
 */
public abstract class OAuth2MessageContext<T1 extends OAuth2Request, T2 extends OAuth2Response, T3 extends Serializable,
        T4 extends Serializable> extends InboundAuthenticationContext {

    private static final long serialVersionUID = -8674054148887113497L;

    public OAuth2MessageContext(T1 request, T2 response, String tenantDomain,
                                Map<T3,T4> parameters) {
        super(request, response, tenantDomain, parameters);
    }

    @Override
    public T1 getRequest(){
        return (T1)super.getRequest();
    }

    public T2 getResponse(){
        return (T2)response;
    }
}
