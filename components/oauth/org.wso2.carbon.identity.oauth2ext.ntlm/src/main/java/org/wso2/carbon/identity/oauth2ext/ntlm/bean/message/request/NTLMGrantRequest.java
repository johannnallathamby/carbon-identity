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

package org.wso2.carbon.identity.oauth2ext.ntlm.bean.message.request;

import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2TokenRequest;

public class NTLMGrantRequest extends OAuth2TokenRequest {

    private static final long serialVersionUID = -3009563708954787261L;

    private String windowsToken;

    public String getWindowsToken() {
        return windowsToken;
    }

    public void setWindowsToken(String windowsToken) {
        this.windowsToken = windowsToken;
    }
}
