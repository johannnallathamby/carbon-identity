/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.inbound;

import javax.servlet.http.Cookie;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class InboundAuthenticationRequest <T extends InboundAuthenticationRequestBuilder> implements Serializable {

    private static final long serialVersionUID = -7281184973045433976L;

    private Map<String, String> headers = new HashMap<String, String>();
    private Map<String, Cookie> cookies = new HashMap<String, Cookie>();
    private Map<String, String[]> parameters = new HashMap<String, String[]>();
    protected String tenantDomain;

    public Map<String, String> getHeaders() {
        return Collections.unmodifiableMap(headers);
    }

    public Map<String, Cookie> getCookies() {
        return Collections.unmodifiableMap(cookies);
    }

    public Map<String, String[]> getParameters() {
        return Collections.unmodifiableMap(parameters);
    }

    public String[] getParameterValues(String paramName) {
        return parameters.get(paramName);
    }

    public String getParameterValue(String paramName) {
        String[] values = parameters.get(paramName);
        if(values.length > 0){
            return values[0];
        }
        return null;
    }

    public String getTenantDomain(){
        return this.tenantDomain;
    }

    protected InboundAuthenticationRequest(T builder) {
        this.headers = builder.headers;
        this.cookies = builder.cookies;
        this.parameters = builder.parameters;
        this.tenantDomain = builder.tenantDomain;
    }
}
