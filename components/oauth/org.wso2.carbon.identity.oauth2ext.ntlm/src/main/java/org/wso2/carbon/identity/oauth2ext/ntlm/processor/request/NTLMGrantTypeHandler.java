/*
*Copyright (c) 2005-2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2ext.ntlm.processor.request;

import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.catalina.Realm;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.GrantType;
import org.wso2.carbon.identity.oauth.handler.token.AbstractGrantTypeHandler;
import org.wso2.carbon.identity.oauth.model.context.TokenMessageContext;
import waffle.apache.NegotiateAuthenticator;
import waffle.util.Base64;
import waffle.windows.auth.IWindowsCredentialsHandle;
import waffle.windows.auth.impl.WindowsAccountImpl;
import waffle.windows.auth.impl.WindowsCredentialsHandleImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

public class NTLMGrantTypeHandler extends AbstractGrantTypeHandler {

    private static Log log = LogFactory.getLog(NTLMGrantTypeHandler.class);

    private static final String securityPackage = "Negotiate";

    @Override
    public boolean canHandle(TokenMessageContext messageContext) throws OAuthSystemException {
        if(messageContext.getRequest().getGrantType() != null &&
                messageContext.getRequest().getGrantType().equals(GrantType.IWA_NTLM.toString())){
            return true;
        }
        return false;
    }

    @Override
    public boolean validateGrant(TokenMessageContext messageContext) throws OAuthSystemException {

        String token = messageContext.getRequest().getWindowsToken();
        if(token == null){
            if (log.isDebugEnabled()) {
                log.debug("NTLM token is null");
            }
            return false;
        } else {
            if(log.isDebugEnabled()){
                log.debug("Received NTLM Token : " + token);
            }
        }

        boolean authenticated;

        NegotiateAuthenticator _authenticator = initializeNegotiateAuthenticator();

        // Logging the windows authentication object
        if (log.isDebugEnabled()) {
            log.debug("Received Windows Token : " + token);
        }

        // client credentials handle
        IWindowsCredentialsHandle clientCredentials = WindowsCredentialsHandleImpl
                .getCurrent(securityPackage);
        clientCredentials.initialize();
        // initial client security context
        WindowsSecurityContextImpl clientContext = new WindowsSecurityContextImpl();
        clientContext.setToken(token.getBytes());
        clientContext.setPrincipalName(WindowsAccountImpl.getCurrentUsername());
        clientContext.setCredentialsHandle(clientCredentials.getHandle());
        clientContext.setSecurityPackage(securityPackage);
        clientContext.initialize(null, null,WindowsAccountImpl.getCurrentUsername());

        while(true){

            SimpleHttpRequest request = new SimpleHttpRequest();
            request.addHeader("Authorization", securityPackage + " "
                    + token);
            SimpleHttpResponse response = new SimpleHttpResponse();
            authenticated = _authenticator.authenticate(request, response, null);
            if (log.isDebugEnabled()) {
                if(authenticated){
                    log.debug("Integrated Windows Authentication was successful");
                }else{
                    log.debug("Integrated Windows Authentication was failed");
                }
            }
            if(authenticated){
                String resourceOwnerUserNameWithDomain=  WindowsAccountImpl.getCurrentUsername();
                String resourceOwnerUserName=  resourceOwnerUserNameWithDomain.split("\\\\")[1];
                messageContext.addProperty("WindowsUser", resourceOwnerUserName);
                break;
            } else if(response.getHeader("WWW-Authenticate").startsWith(securityPackage + " ") && response.getStatus() == 401){
                String continueToken = response.getHeader("WWW-Authenticate").substring(securityPackage.length() + 1);
                byte[] continueTokenBytes = Base64.decode(continueToken);
                if(continueTokenBytes.length > 0){
                    token = continueToken;
                }
            } else {
                break;
            }
        }
        return authenticated;
    }

    private NegotiateAuthenticator initializeNegotiateAuthenticator() {
        NegotiateAuthenticator _authenticator = new NegotiateAuthenticator();
        SimpleContext ctx = new SimpleContext();
        Realm realm = new SimpleRealm();
        ctx.setRealm(realm);
        _authenticator.setContainer(ctx);
        return _authenticator;
    }
}
