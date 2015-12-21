/*
*Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth.common.GrantType;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.handler.token.AbstractGrantTypeHandler;
import org.wso2.carbon.identity.oauth.internal.OAuthServiceComponent;
import org.wso2.carbon.identity.oauth.model.context.TokenMessageContext;
import org.wso2.carbon.identity.oauth.model.message.request.token.OAuthTokenRequest;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * This implements SAML 2.0 Bearer Assertion Profile for OAuth 2.0 -
 * http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-14.
 */
public class SAML2BearerGrantHandler extends AbstractGrantTypeHandler {

    private static Log log = LogFactory.getLog(SAML2BearerGrantHandler.class);

    SAMLSignatureProfileValidator profileValidator = null;

    public void init(Properties properties) throws OAuthSystemException {

        super.init(properties);

        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(this.getClass().getClassLoader());

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            log.error(e.getMessage(),e);
            throw new OAuthSystemException("Error in bootstrapping the OpenSAML2 library");
        } finally {
            thread.setContextClassLoader(loader);
        }

        profileValidator =  new SAMLSignatureProfileValidator();
    }

    @Override
    public boolean canHandle(TokenMessageContext messageContext) throws OAuthSystemException {
        if(messageContext.getRequest().getGrantType() != null &&
                messageContext.getRequest().getGrantType().equals(GrantType.SAML20_BEARER.toString())){
            return true;
        }
        return false;
    }

    /**
     * We're validating the SAML token that we receive from the request. Through the assertion parameter is the POST
     * request. A request format that we handle here looks like,
     * <p/>
     * POST /token.oauth2 HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * <p/>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer&
     * assertion=PHNhbWxwOl...[omitted for brevity]...ZT4
     *
     *
     * @param messageContext Token message request context
     * @return true if validation is successful, false otherwise
     */
    @Override
    public boolean validateGrant(TokenMessageContext messageContext) throws OAuthSystemException {

        OAuthTokenRequest request = messageContext.getRequest();

        // Logging the SAML token
        if (log.isDebugEnabled()) {
            log.debug("Received SAML assertion : " +
                    new String(Base64.decode(request.getAssertion()))
            );
        }

        XMLObject samlObject = null;
        try {
            samlObject = unmarshall(new String(Base64.decode(request.getAssertion())));
        } catch (OAuthSystemException e) {
            return false;
        }
        Assertion assertion = (Assertion) samlObject;

        if (assertion == null) {
            log.debug("Assertion is null, cannot continue");
            return false;
        }

        /**
         * The Assertion MUST contain a <Subject> element.  The subject MAY identify the resource owner for whom
         * the access token is being requested.  For client authentication, the Subject MUST be the "client_id"
         * of the OAuth client.  When using an Assertion as an authorization grant, the Subject SHOULD identify
         * an authorized accessor for whom the access token is being requested (typically the resource owner, or
         * an authorized delegate).  Additional information identifying the subject/principal of the transaction
         * MAY be included in an <AttributeStatement>.
         */
        if (assertion.getSubject() != null) {
            String resourceOwnerUserName = assertion.getSubject().getNameID().getValue();
            messageContext.addProperty("SAML2AssertionUserID", resourceOwnerUserName);
            if (resourceOwnerUserName == null || resourceOwnerUserName.equals("")) {
                log.debug("NameID in Assertion cannot be empty");
                return false;
            }
        } else {
            log.debug("Cannot find a Subject in the Assertion");
            return false;
        }

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if(request.getTenantDomain() != null && !"".equals(request.getTenantDomain())){
            tenantDomain = request.getTenantDomain();
        }

        /**
         * Validating SAML request according to criteria specified in "SAML 2.0 Bearer Assertion Profiles for
         * OAuth 2.0 - http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-14
         */

        /**
         * The Assertion's <Issuer> element MUST contain a unique identifier for the entity that issued
         * the Assertion.
         */
        IdentityProvider identityProvider = null;
        String tokenEndpointAlias = null;
        if (assertion.getIssuer() == null || assertion.getIssuer().getValue().equals("")) {
            log.debug("Issuer is empty in the SAML assertion");
            return false;
        } else {
            try {
                identityProvider = IdentityProviderManager.getInstance().getIdPByAuthenticatorPropertyValue(
                        "IdPEntityId", assertion.getIssuer().getValue(), tenantDomain, false);

                // IF Federated IDP not found get the resident IDP and check, resident IDP entityID == issuer
                if (identityProvider == null || !identityProvider.isEnable()) {

                    identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
                    FederatedAuthenticatorConfig[] fedAuthnConfigs = identityProvider.getFederatedAuthenticatorConfigs();

                    String idpEntityId = null;
                    // Get SAML authenticator
                    FederatedAuthenticatorConfig samlAuthenticatorConfig = IdentityApplicationManagementUtil.getFederatedAuthenticator(
                            fedAuthnConfigs, IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
                    // Get Entity ID from SAML authenticator
                    Property samlProperty = IdentityApplicationManagementUtil.getProperty(samlAuthenticatorConfig.getProperties(),
                            IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
                    if (samlProperty != null) {
                        idpEntityId = samlProperty.getValue();
                        if (idpEntityId == null || !assertion.getIssuer().getValue().equals(idpEntityId)) {
                            log.debug("SAML Token Issuer verification failed. Issuer not registered");
                            return false;
                        }
                    }

                    // Get OpenIDConnect authenticator == OAuth authenticator
                    FederatedAuthenticatorConfig oauthAuthenticatorConfig = IdentityApplicationManagementUtil.getFederatedAuthenticator(
                            fedAuthnConfigs, IdentityApplicationConstants.Authenticator.OIDC.NAME);
                    // Get  OAuth token endpoint
                    Property oauthProperty = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                            IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL);
                    if (oauthProperty != null) {
                        tokenEndpointAlias = oauthProperty.getValue();
                    }

                } else {
                    // Get Alias from Federated IDP
                    tokenEndpointAlias = identityProvider.getAlias();
                }
            } catch (IdentityApplicationManagementException e) {
                log.debug("Error while getting Federated Identity Provider ");
            }
        }

        /**
         * The Assertion MUST contain <Conditions> element with an <AudienceRestriction> element with an <Audience>
         * element containing a URI reference that identifies the authorization server, or the service provider
         * SAML entity of its controlling domain, as an intended audience.  The token endpoint URL of the
         * authorization server MAY be used as an acceptable value for an <Audience> element.  The authorization
         * server MUST verify that it is an intended audience for the Assertion.
         */
        if(tokenEndpointAlias == null || tokenEndpointAlias.equals("")){
            String errorMsg = "Token Endpoint alias of the local Identity Provider has not been " +
                    "configured for " + identityProvider.getIdentityProviderName();
            log.debug(errorMsg);
            return false;
        }
            Conditions conditions = assertion.getConditions();
            if (conditions != null) {
                List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
                if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                    boolean audienceFound = false;
                    for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                        if (audienceRestriction.getAudiences() != null && audienceRestriction.getAudiences().size() > 0) {
                            for(Audience audience: audienceRestriction.getAudiences()){
                                if(audience.getAudienceURI().equals(tokenEndpointAlias)){
                                    audienceFound = true;
                                    break;
                                }
                            }
                        }
                        if(audienceFound){
                            break;
                        }
                    }
                    if(!audienceFound){
                        if(log.isDebugEnabled()){
                            String message = "SAML Assertion Audience Restriction validation failed";
                             log.debug(message);
                        }
                        return false;
                    }
                } else {
                    if(log.isDebugEnabled()){
                        String message = "SAML Assertion doesn't contain AudienceRestrictions";
                        log.debug(message);
                    }
                    return false;
                }
            } else {
                if(log.isDebugEnabled()){
                    String message = "SAML Assertion doesn't contain Conditions";
                    log.debug(message);
                }
                return false;
            }



        /**
         * The Assertion MUST have an expiry that limits the time window during which it can be used.  The expiry
         * can be expressed either as the NotOnOrAfter attribute of the <Conditions> element or as the NotOnOrAfter
         * attribute of a suitable <SubjectConfirmationData> element.
         */

        /**
         * The <Subject> element MUST contain at least one <SubjectConfirmation> element that allows the
         * authorization server to confirm it as a Bearer Assertion.  Such a <SubjectConfirmation> element MUST
         * have a Method attribute with a value of "urn:oasis:names:tc:SAML:2.0:cm:bearer".  The
         * <SubjectConfirmation> element MUST contain a <SubjectConfirmationData> element, unless the Assertion
         * has a suitable NotOnOrAfter attribute on the <Conditions> element, in which case the
         * <SubjectConfirmationData> element MAY be omitted. When present, the <SubjectConfirmationData> element
         * MUST have a Recipient attribute with a value indicating the token endpoint URL of the authorization
         * server (or an acceptable alias).  The authorization server MUST verify that the value of the Recipient
         * attribute matches the token endpoint URL (or an acceptable alias) to which the Assertion was delivered.
         * The <SubjectConfirmationData> element MUST have a NotOnOrAfter attribute that limits the window during
         * which the Assertion can be confirmed.  The <SubjectConfirmationData> element MAY also contain an Address
         * attribute limiting the client address from which the Assertion can be delivered.  Verification of the
         * Address is at the discretion of the authorization server.
         */

        DateTime notOnOrAfterFromConditions = null;
        Set<DateTime> notOnOrAfterFromSubjectConfirmations = new HashSet<DateTime>();
        boolean bearerFound = false;
        ArrayList<String> recipientURLS = new ArrayList<String>();

        if (assertion.getConditions() != null && assertion.getConditions().getNotOnOrAfter() != null) {
            notOnOrAfterFromConditions = assertion.getConditions().getNotOnOrAfter();
        }

        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if (subjectConfirmations != null && !subjectConfirmations.isEmpty()) {
            for (SubjectConfirmation s : subjectConfirmations) {
                if(s.getMethod() != null){
                    if (s.getMethod().equals(OAuthConstants.OAUTH2_SAML2_BEARER_METHOD)) {
                        bearerFound = true;
                    }
                } else {
                    log.debug("Cannot find Method attribute in SubjectConfirmation " + s.toString());
                    return false;
                }

                if(s.getSubjectConfirmationData() != null) {
                    if(s.getSubjectConfirmationData().getRecipient() != null){
                        recipientURLS.add(s.getSubjectConfirmationData().getRecipient());
                    }
                    if(s.getSubjectConfirmationData().getNotOnOrAfter() != null){
                        notOnOrAfterFromSubjectConfirmations.add(s.getSubjectConfirmationData().getNotOnOrAfter());
                    } else {
                        log.debug("Cannot find NotOnOrAfter attribute in SubjectConfirmationData " +
                                s.getSubjectConfirmationData().toString());
                        return false;
                    }
                } else if (s.getSubjectConfirmationData() == null && notOnOrAfterFromConditions == null) {
                    log.debug("Neither can find NotOnOrAfter attribute in Conditions nor SubjectConfirmationData" +
                            "in SubjectConfirmation " + s.toString());
                    return false;
                }
            }
        } else {
            log.debug("No SubjectConfirmation exist in Assertion");
            return false;
        }

        if (!bearerFound) {
            log.debug("Failed to find a SubjectConfirmation with a Method attribute having : " +
                    OAuthConstants.OAUTH2_SAML2_BEARER_METHOD);
            return false;
        }

        if(recipientURLS.size() > 0){
            if(!recipientURLS.contains(tokenEndpointAlias)){
                log.debug("None of the recipient URLs match the token endpoint or an acceptable alias");
                return false;
            }
        }

        /**
         * The authorization server MUST verify that the NotOnOrAfter instant has not passed, subject to allowable
         * clock skew between systems.  An invalid NotOnOrAfter instant on the <Conditions> element invalidates
         * the entire Assertion.  An invalid NotOnOrAfter instant on a <SubjectConfirmationData> element only
         * invalidates the individual <SubjectConfirmation>.  The authorization server MAY reject Assertions with
         * a NotOnOrAfter instant that is unreasonably far in the future.  The authorization server MAY ensure
         * that Bearer Assertions are not replayed, by maintaining the set of used ID values for the length of
         * time for which the Assertion would be considered valid based on the applicable NotOnOrAfter instant.
         */
        if (notOnOrAfterFromConditions != null && notOnOrAfterFromConditions.compareTo(new DateTime()) < 1) {
            // notOnOrAfter is an expired timestamp
            log.debug("NotOnOrAfter is having an expired timestamp in Conditions element");
            return false;
        }
        boolean validSubjectConfirmationDataExists = false;
        if(!notOnOrAfterFromSubjectConfirmations.isEmpty()){
            for(DateTime entry : notOnOrAfterFromSubjectConfirmations){
                if(entry.compareTo(new DateTime()) >= 1){
                    validSubjectConfirmationDataExists = true;
                }
            }
        }
        if(notOnOrAfterFromConditions == null && !validSubjectConfirmationDataExists){
            log.debug("No valid NotOnOrAfter element found in SubjectConfirmations");
            return false;
        }

        /**
         * The Assertion MUST be digitally signed by the issuer and the authorization server MUST verify the
         * signature.
         */

        try {
            profileValidator.validate(assertion.getSignature());
        } catch (ValidationException e) {
            // Indicates signature did not conform to SAML Signature profile
            log.debug(e.getMessage());
            return false;
        }

        X509Certificate x509Certificate = null;
        try {
            x509Certificate = (X509Certificate)IdentityApplicationManagementUtil
                    .decodeCertificate(identityProvider.getCertificate());
        } catch (CertificateException e) {
            log.error(e.getMessage(), e);
            throw new OAuthSystemException("Error occurred while decoding public certificate of Identity Provider "
                    + identityProvider.getIdentityProviderName() + " for tenant domain " + tenantDomain);
        }

        try {
            X509Credential x509Credential = new X509CredentialImpl(x509Certificate);
            SignatureValidator signatureValidator = new SignatureValidator(x509Credential);
            signatureValidator.validate(assertion.getSignature());
            log.debug("Signature validation successful");
        } catch (ValidationException e) {
            log.debug(e.getMessage(), e);
            return false;
        }

        messageContext.setApprovedScope(request.getRequestedScopes());

        // Storing the Assertion for further use. This will be used in OpenID Connect for example
        messageContext.addProperty(OAuthConstants.MessageContext.OAUTH_SAML2_ASSERTION, assertion);

        return true;
    }

    /**
     * Constructing the SAML or XACML Objects from a String
     * @param xmlString Decoded SAML or XACML String
     * @return SAML or XACML Object
     * @throws OAuthSystemException
     *
     */
    private XMLObject unmarshall(String xmlString) throws OAuthSystemException {
        Unmarshaller unmarshaller;
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(xmlString.trim().getBytes()));
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (Exception e) {
            log.debug("Error in constructing XML Object from the encoded String", e);
            throw new OAuthSystemException("Error in constructing XML Object from the encoded String", e);
        }
    }

    /**
     * Helper method to get tenantId from tenantDomain
     *
     * @param tenantDomain
     * @return tenantId
     * @throws OAuthSystemException
     */
    private int getTenantId(String tenantDomain) throws OAuthSystemException {

        RealmService realmService = OAuthServiceComponent.getRealmService();
        try {
            return realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            log.debug(e.getMessage(), e);
            //do not log
            throw new OAuthSystemException("Error occurred while obtaining tenantId from tenantDomain " + tenantDomain);
        }
    }

}
