/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.apache.sling.auth.saml2.sp;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.io.IOUtils;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.SlingServletException;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.saml2.AuthenticationHandlerSAML2;
import org.apache.sling.auth.saml2.SAML2ConfigService;
import org.apache.sling.auth.saml2.Saml2UserMgtService;
import org.apache.sling.auth.saml2.idp.IDPCredentials;
import org.apache.sling.auth.saml2.impl.Saml2Credentials;
import org.apache.sling.auth.saml2.sync.Saml2User;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.apache.sling.auth.saml2.Helpers;
import org.apache.sling.auth.saml2.idp.ArtifactResolutionServlet;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.wiring.BundleWiring;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;


import javax.jcr.RepositoryException;
import javax.servlet.Servlet;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import static org.apache.sling.api.servlets.ServletResolverConstants.*;


@Component(
        service = Servlet.class,
        immediate=true,
        configurationPid = "org.apache.sling.auth.saml2.impl.SAML2ConfigServiceImpl",
        configurationPolicy = ConfigurationPolicy.REQUIRE,
        property = {
            SLING_SERVLET_PATHS+"=/sp/consumer",
            SLING_SERVLET_METHODS+"=GET",
            "sling.auth.requirements=-/sp/consumer"
        }
)

public class ConsumerServlet extends SlingAllMethodsServlet {

    public static final String SP_ENTITY_ID = "TestSP";
    public static final String AUTHENTICATED_SESSION_ATTRIBUTE = "authenticated";
    public static final String EXT_USER_SESSION_ATTRIBUTE = "extuser";
    public static final String GOTO_URL_SESSION_ATTRIBUTE = "gotoURL";
    public static final String ASSERTION_CONSUMER_SERVICE = "http://localhost:8080/sp/consumer";
    public static final String NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    @Reference
    private Saml2UserMgtService saml2UserMgtService;
    @Reference
    private SAML2ConfigService saml2ConfigService;
    private static Logger logger = LoggerFactory.getLogger(ConsumerServlet.class);
    private String uidAttrName = "";

    @Activate
    protected void activate() {
        this.uidAttrName = saml2ConfigService.getSaml2userIDAttr();

    }

    private void doClassloading(){
        BundleWiring bundleWiring = FrameworkUtil.getBundle(ConsumerServlet.class).adapt(BundleWiring.class);
        ClassLoader loader = bundleWiring.getClassLoader();
        Thread thread = Thread.currentThread();
        thread.setContextClassLoader(loader);
    }

    @Override
    protected void doPost(final SlingHttpServletRequest req, final SlingHttpServletResponse resp)
            throws SlingServletException, IOException {
        doClassloading();

        HTTPPostDecoder httpPostDecoder = new HTTPPostDecoder();
        ParserPool parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        httpPostDecoder.setParserPool(parserPool);
        httpPostDecoder.setHttpServletRequest(req);

        try {
            httpPostDecoder.initialize();
            httpPostDecoder.decode();

        } catch (MessageDecodingException e) {
            logger.error("MessageDecodingException");
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        MessageContext messageContext = httpPostDecoder.getMessageContext();
        Response response = (Response) messageContext.getMessage();
        EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
        Assertion assertion = decryptAssertion(encryptedAssertion);
        verifyAssertionSignature(assertion);
        logger.info("Decrypted Assertion: ");
        Helpers.logSAMLObject(assertion);

        logAssertionAttributes(assertion);
        logAuthenticationInstant(assertion);
        logAuthenticationMethod(assertion);

        User extUser = doUserManagement(assertion);
        setAuthenticatedSession(req, extUser);
        redirectToGotoURL(req, resp);
    }




    @Override
    protected void doGet(final SlingHttpServletRequest req, final SlingHttpServletResponse resp)
            throws SlingServletException, IOException {
        doClassloading();
//start soap
        logger.info("Artifact received");
        Artifact artifact = buildArtifactFromRequest(req);
        logger.info("Artifact: " + artifact.getArtifact());
        ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
        logger.info("Sending ArtifactResolve");
        logger.info("ArtifactResolve: ");
        Helpers.logSAMLObject(artifactResolve);
        ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve, resp);
        logger.info("ArtifactResponse received");
        logger.info("ArtifactResponse: ");
        Helpers.logSAMLObject(artifactResponse);
        validateDestinationAndLifetime(artifactResponse, req);
// end soap
        EncryptedAssertion encryptedAssertion = getEncryptedAssertion(artifactResponse);
        Assertion assertion = decryptAssertion(encryptedAssertion);
        verifyAssertionSignature(assertion);
        logger.info("Decrypted Assertion: ");
        Helpers.logSAMLObject(assertion);

        logAssertionAttributes(assertion);
        logAuthenticationInstant(assertion);
        logAuthenticationMethod(assertion);

        User extUser = doUserManagement(assertion);
        setAuthenticatedSession(req, extUser);
        redirectToGotoURL(req, resp);
    }

    private Artifact buildArtifactFromRequest(final SlingHttpServletRequest req) {
        Artifact artifact = Helpers.buildSAMLObject(Artifact.class);
        // XSS
        artifact.setArtifact(req.getParameter("SAMLart"));
        return artifact;
    }

    private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        ArtifactResolve artifactResolve = Helpers.buildSAMLObject(ArtifactResolve.class);
        Issuer issuer = Helpers.buildSAMLObject(Issuer.class);
        issuer.setValue(ConsumerServlet.SP_ENTITY_ID);
        artifactResolve.setIssuer(issuer);
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setID(Helpers.generateSecureRandomId());
        artifactResolve.setDestination(ArtifactResolutionServlet.ARTIFACT_RESOLUTION_SERVICE);
        artifactResolve.setArtifact(artifact);
        return artifactResolve;
    }

    private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve, SlingHttpServletResponse servletResponse) {
        try {
            MessageContext<ArtifactResolve> contextout = new MessageContext<ArtifactResolve>();
            contextout.setMessage(artifactResolve);
            SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
            signatureSigningParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            SecurityParametersContext securityParametersContext = contextout.getSubcontext(SecurityParametersContext.class, true);
            securityParametersContext.setSignatureSigningParameters(signatureSigningParameters);
            InOutOperationContext<ArtifactResponse, ArtifactResolve> context = new ProfileRequestContext<ArtifactResponse, ArtifactResolve>();
            context.setOutboundMessageContext(contextout);
            AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject> soapClient = new AbstractPipelineHttpSOAPClient() {
                protected HttpClientMessagePipeline newPipeline() throws SOAPException {
                    HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
                    HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();
                    BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(
                            encoder,
                            decoder
                    );
                    pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
                    return pipeline;
                }};
            HttpClientBuilder clientBuilder = new HttpClientBuilder();
            soapClient.setHttpClient(clientBuilder.buildClient());
            soapClient.send(ArtifactResolutionServlet.ARTIFACT_RESOLUTION_SERVICE, context);
            return context.getInboundMessageContext().getMessage();
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void validateDestinationAndLifetime(ArtifactResponse artifactResponse, SlingHttpServletRequest request) {
        MessageContext context = new MessageContext<ArtifactResponse>();
        context.setMessage(artifactResponse);
        SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
        messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());
        MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
        lifetimeSecurityHandler.setClockSkew(1000);
        lifetimeSecurityHandler.setMessageLifetime(2000);
        lifetimeSecurityHandler.setRequiredRule(true);
        ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
        receivedEndpointSecurityHandler.setHttpServletRequest(request);
        List handlers = new ArrayList<MessageHandler>();
        handlers.add(lifetimeSecurityHandler);
        handlers.add(receivedEndpointSecurityHandler);
        BasicMessageHandlerChain<ArtifactResponse> handlerChain = new BasicMessageHandlerChain<ArtifactResponse>();
        handlerChain.setHandlers(handlers);
        try {
            handlerChain.initialize();
            handlerChain.doInvoke(context);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageHandlerException e) {
            throw new RuntimeException(e);
        }
    }
    private EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response)artifactResponse.getMessage();
        return response.getEncryptedAssertions().get(0);
    }

    private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(SPCredentials.getCredential());
        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);
        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }

    private void verifyAssertionSignature(Assertion assertion) {
        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }
        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());
            SignatureValidator.validate(assertion.getSignature(), IDPCredentials.getCredential());
            logger.info("SAML Assertion signature verified");
        } catch (SignatureException e) {
            e.printStackTrace();
            logger.error("SAML Assertion signature problem", e);
        }
    }

    private void logAssertionAttributes(Assertion assertion) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            logger.info("Attribute name: " + attribute.getName());
            for (XMLObject attributeValue : attribute.getAttributeValues()) {
                logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
            }
        }
    }

    private void logAuthenticationInstant(Assertion assertion) {
        logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
    }

    private void logAuthenticationMethod(Assertion assertion) {
        logger.info("Authentication method: " + assertion.getAuthnStatements().get(0)
                .getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
    }

    private void setAuthenticatedSession(SlingHttpServletRequest req, User user) {
        req.getSession().setAttribute(ConsumerServlet.AUTHENTICATED_SESSION_ATTRIBUTE, true);
        try {
            AuthenticationInfo authInfo = new AuthenticationInfo(AuthenticationHandlerSAML2.AUTH_TYPE, user.getID());
            //AUTHENTICATION_INFO_CREDENTIALS
            authInfo.put("user.jcr.credentials", new Saml2Credentials(user.getID()));
            SessionStorage sessionStorage = new SessionStorage(saml2ConfigService.getSaml2SessionAttr());
            sessionStorage.setAuthInfo(req, authInfo);
        } catch (RepositoryException e) {
            logger.error("failed to set Authentication Info", e);
        }
    }

    private void redirectToGotoURL(SlingHttpServletRequest req, SlingHttpServletResponse resp) {
        String gotoURL = (String)req.getSession().getAttribute(ConsumerServlet.GOTO_URL_SESSION_ATTRIBUTE);
        logger.info("Redirecting to requested URL: " + gotoURL);
        try {
            resp.sendRedirect(gotoURL);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private User doUserManagement(Assertion assertion) {
        if (assertion.getAttributeStatements() == null ||
                assertion.getAttributeStatements().get(0) == null ||
                assertion.getAttributeStatements().get(0).getAttributes() == null) {
            logger.warn("SAML Assertion Attribute Statement or Attributes was null ");
            return null;
        }
        // start a user object
        Saml2User saml2User = new Saml2User();
        // iterate the attribute assertions
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            if (attribute.getName().equals(saml2ConfigService.getSaml2userIDAttr())) {
                logger.debug("username attr name: " + attribute.getName());
                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                    if ( ((XSString) attributeValue).getValue() != null ) {
                        saml2User.setId( ((XSString) attributeValue).getValue());
                        logger.debug("username value: " + saml2User.getId());
                    }
                }
            } else if (attribute.getName().equals(saml2ConfigService.getSaml2groupMembershipAttr())) {
                logger.debug("group attr name: " + attribute.getName());
                for (XMLObject attributeValue : attribute.getAttributeValues()) {
                    if ( ((XSString) attributeValue).getValue() != null ) {
                        saml2User.addGroupMembership( ((XSString) attributeValue).getValue());
                        logger.debug("managed group {} added: ", ((XSString) attributeValue).getValue());
                    }
                }
            }
        }

        boolean setUpOk = saml2UserMgtService.setUp();
        if (setUpOk) {
            User samlUser = saml2UserMgtService.getOrCreateSamlUser(saml2User);
            saml2UserMgtService.updateGroupMembership(saml2User);
            saml2UserMgtService.cleanUp();
            return samlUser;
        }
        return null;
    }
}
