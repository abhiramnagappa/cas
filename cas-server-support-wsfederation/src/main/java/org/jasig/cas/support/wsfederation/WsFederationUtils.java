/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.cas.support.wsfederation;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import org.jasig.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.impl.AssertionImpl;
import org.opensaml.ws.wsfed.RequestedSecurityToken;
import org.opensaml.ws.wsfed.impl.RequestSecurityTokenResponseImpl;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public final class WsFederationUtils {
    
    private static final Logger logger = LoggerFactory.getLogger(WsFederationUtils.class);
    
    static{
        try { 
            // Initialize the library
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException ex) {
            logger.error(ex.getMessage());
        }
    }
    
    public static WsFederationCredential createCredentialFromToken(String wresult) 
            throws Exception{

        WsFederationCredential credential = new WsFederationCredential();

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);
        InputStream in = new ByteArrayInputStream(wresult.getBytes("UTF-8"));

        org.w3c.dom.Document document = ppMgr.parse(in);
        org.w3c.dom.Element metadataRoot = document.getDocumentElement();

        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
        RequestSecurityTokenResponseImpl authRequest = (RequestSecurityTokenResponseImpl) unmarshaller.unmarshall(metadataRoot);

        List<RequestedSecurityToken> rst = authRequest.getRequestedSecurityToken();
        AssertionImpl assertion = (AssertionImpl) rst.get(0).getSecurityTokens().get(0);

        SignatureValidation(assertion);
        
        credential.setIssuer(assertion.getIssuer());
        credential.setAudience(assertion.getConditions().getAudienceRestrictionConditions().get(0).getAudiences().get(0).getUri());
        credential.setAuthenticationMethod(assertion.getAuthenticationStatements().get(0).getAuthenticationMethod());
        //logger.debug("Subject: " + assrt.getSubjectStatements().get(0).getSubject());
        credential.setId(assertion.getID());
        
        Map<String,Object> attributes = new HashMap<String,Object>();
        for (Attribute item : assertion.getAttributeStatements().get(0).getAttributes()) {
            attributes.put(item.getAttributeName() ,((XSAny)item.getAttributeValues().get(0)).getTextContent());
        }

        credential.setAttributes(attributes);
        return credential;
    }

    private static boolean SignatureValidation(AssertionImpl assrt)  {
 
        //create SignatureValidator
        SignatureValidator signatureValidator = null;
        
        try {
            signatureValidator = new SignatureValidator(getSigningCredential("signing.cer"));
        } catch (FileNotFoundException ex) {
            java.util.logging.Logger.getLogger(WsFederationUtils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            java.util.logging.Logger.getLogger(WsFederationUtils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(WsFederationUtils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(WsFederationUtils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            java.util.logging.Logger.getLogger(WsFederationUtils.class.getName()).log(Level.SEVERE, null, ex);
        }

        //get the signature to validate from the response object
        Signature signature = assrt.getSignature();

        //try to validate
        try 
        {
            signatureValidator.validate(signature);
        }
        catch (ValidationException ve) 
        {
            logger.warn("Signature is NOT valid.");
            logger.warn(ve.getMessage());
            return false;
        }
        
        return true;
    }

    private static BasicX509Credential getSigningCredential(String filename) throws FileNotFoundException, CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //grab the certificate file
        File certificateFile = new File(filename); 

        //get the certificate from the file
        InputStream inputStream2 = new FileInputStream(certificateFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(inputStream2);
        inputStream2.close();

        //pull out the public key part of the certificate into a KeySpec
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());

        //get KeyFactory object that creates key objects, specifying RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        System.out.println("Security Provider: " + keyFactory.getProvider().toString());

        //generate public key to validate signatures
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        //create credentials
        BasicX509Credential publicCredential = new BasicX509Credential();

        //add public key value
        publicCredential.setPublicKey(publicKey);

        return publicCredential;
    }
}
