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
 *
 */

package org.wso2.carbon.identity.application.authentication.framework.inbound;

import javax.servlet.http.Cookie;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class InboundAuthenticationResponse implements Serializable {

    private static final long serialVersionUID = 4371843418083025682L;

    private Map<String, String> headers = new HashMap<String, String>();
    private Map<String, Cookie> cookies = new HashMap<String, Cookie>();
    private Map<String, String[]> parameters = new HashMap<>();
    private String body;
    private int statusCode;
    private String redirectURL;

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

    public int getStatusCode() {
        return statusCode;
    }

    public String getRedirectURL() {
        return redirectURL;
    }

    public String getBody() {
        return body;
    }

    protected InboundAuthenticationResponse(InboundAuthenticationResponseBuilder builder) {
        this.headers = builder.headers;
        this.cookies = builder.cookies;
        this.parameters = builder.parameters;
        this.statusCode = builder.statusCode;
        this.redirectURL = builder.redirectURL;
        this.body = builder.body;

    }

    public static class InboundAuthenticationResponseBuilder {

        private Map<String, String> headers = new HashMap<String, String>();
        private Map<String, Cookie> cookies = new HashMap<String, Cookie>();
        private Map<String, String[]> parameters = new HashMap<>();
        private int statusCode;
        private String redirectURL;
        private String body;

        public String getName(){
            return "InboundAuthenticationResponseBuilder";
        }

        public int getPriority() {
            return 0;
        }

        public InboundAuthenticationResponseBuilder() {

        }

        public InboundAuthenticationResponseBuilder setHeaders(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        public InboundAuthenticationResponseBuilder addResponseHeaders(Map<String,String> headers) {
            for(Map.Entry<String,String> header:headers.entrySet()) {
                if(this.headers.containsKey(header.getKey())) {
                    throw AuthenticationFrameworkRuntimeException.error("Headers map trying to override existing " +
                            "header " + header.getKey());
                }
                this.headers.put(header.getKey(), header.getValue());
            }
            return this;
        }

        public InboundAuthenticationResponseBuilder setCookies(Map<String, Cookie> cookies) {
            this.cookies = cookies;
            return this;
        }

        public InboundAuthenticationResponseBuilder addCookies(Map<String,Cookie> cookies) {
            for(Map.Entry<String,Cookie> cookie:cookies.entrySet()) {
                if(this.cookies.containsKey(cookie.getKey())) {
                    throw AuthenticationFrameworkRuntimeException.error("Cookies map trying to override existing " +
                            "cookie " + cookie.getKey());
                }
                this.cookies.put(cookie.getKey(), cookie.getValue());
            }
            return this;
        }

        public InboundAuthenticationResponseBuilder setParameters(Map<String,String[]> parameters) {
            this.parameters = parameters;
            return this;
        }

        public InboundAuthenticationResponseBuilder addParameters(Map<String,String[]> parameters) {
            for(Map.Entry<String,String[]> parameter:parameters.entrySet()) {
                if(this.parameters.containsKey(parameter.getKey())) {
                    throw AuthenticationFrameworkRuntimeException.error("Parameters map trying to override existing " +
                            "key " + parameter.getKey());
                }
                this.parameters.put(parameter.getKey(), parameter.getValue());
            }
            return this;
        }

        public InboundAuthenticationResponseBuilder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public InboundAuthenticationResponseBuilder setRedirectURL(String redirectURL) {
            this.redirectURL = redirectURL;
            return this;
        }

        public InboundAuthenticationResponseBuilder setBody(String body) {
            this.body = body;
            return this;
        }

        public InboundAuthenticationResponse build() {
            return new InboundAuthenticationResponse(this);
        }

    }
}
