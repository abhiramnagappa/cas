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
import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.jasig.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.impl.AssertionImpl;
import org.opensaml.ws.wsfed.RequestedSecurityToken;
import org.opensaml.ws.wsfed.impl.RequestSecurityTokenResponseImpl;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** 
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
    
    public static AssertionImpl parseTokenString(String wresult)  {
        RequestSecurityTokenResponseImpl rsToken;
                
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);

        try {
            InputStream in = new ByteArrayInputStream(wresult.getBytes("UTF-8"));
            Document document = parserPool.parse(in);
            Element metadataRoot = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
            rsToken = (RequestSecurityTokenResponseImpl) unmarshaller.unmarshall(metadataRoot);
        } catch (UnmarshallingException ex) {
            logger.warn(ex.getMessage());
            return null;
        } catch (XMLParserException ex) {
            logger.warn(ex.getMessage());
            return null;
        } catch (UnsupportedEncodingException ex) {
            logger.warn(ex.getMessage());
            return null;
        }
        //Get our (Saml1) token
        List<RequestedSecurityToken> rst = rsToken.getRequestedSecurityToken();
        AssertionImpl assertion = (AssertionImpl) rst.get(0).getSecurityTokens().get(0);
        
        return assertion;
    }
    
    public static WsFederationCredential createCredentialFromToken(AssertionImpl assertion) {
        DateTime retrievedOn = new DateTime().withZone(DateTimeZone.UTC);
        WsFederationCredential credential = new WsFederationCredential();
        
        credential.setRetrievedOn(retrievedOn);

        credential.setId(assertion.getID());
        credential.setIssuer(assertion.getIssuer());
        credential.setIssuedOn(assertion.getIssueInstant());

        Conditions conditions = assertion.getConditions();
        if ( conditions != null ) {
            credential.setNotBefore(conditions.getNotBefore());
            credential.setNotOnOrAfter(conditions.getNotOnOrAfter());
            credential.setAudience(conditions.getAudienceRestrictionConditions().get(0).getAudiences().get(0).getUri());
        }
            
        if ( assertion.getAuthenticationStatements() !=null && assertion.getAuthenticationStatements().size() > 0 ) {
            credential.setAuthenticationMethod(assertion.getAuthenticationStatements().get(0).getAuthenticationMethod());
        }

        //retrieve an attributes from the assertion
        HashMap<String,Object> attributes = new HashMap<String,Object>();
        for ( Attribute item : assertion.getAttributeStatements().get(0).getAttributes() ) {
            if ( item.getAttributeValues().size() == 1 ) {
                attributes.put(item.getAttributeName() ,((XSAny)item.getAttributeValues().get(0)).getTextContent());

            } else {

                ArrayList itemList = new ArrayList();

                for ( int i=0; i<item.getAttributeValues().size(); i++ ) {
                    itemList.add(((XSAny)item.getAttributeValues().get(i)).getTextContent());
                }

                if ( !itemList.isEmpty() ) {
                    attributes.put(item.getAttributeName(), itemList);
                }
            }    
        }
        credential.setAttributes(attributes);

        return credential;
    }

    public static boolean validateSignature(AssertionImpl assrt, List<BasicX509Credential> x509Creds)  {
 
        SignatureValidator signatureValidator = null;
        for ( BasicX509Credential cred : x509Creds ) {
            try {
                signatureValidator = new SignatureValidator(cred);
            } catch (Exception ex) {
                logger.warn(ex.getMessage());
                break;
            }

            //get the signature to validate from the response object
            Signature signature = assrt.getSignature();

            //try to validate
            try 
            {
                signatureValidator.validate(signature);
                return true;
            }
            catch (ValidationException ex) 
            {
                logger.warn("Signature is NOT valid.");
                logger.warn(ex.getMessage());
                break;
            }
        }
            return false;
    }

    public static BasicX509Credential getSigningCredential(String filename)  {
        //grab the certificate file
        File certificateFile = new File(filename); 
        BasicX509Credential publicCredential;
        
        //get the certificate from the file
        try {
            InputStream inputStream = new FileInputStream(certificateFile);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(inputStream);
            
            try {
                inputStream.close();
            }
            catch (IOException ex) {
                logger.warn("Error closing the signing cert file: " + ex.getMessage());
            }
            
            //get the public key from the certificate
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());
            
            //generate public key to validate signatures
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            
            //add the public key
            publicCredential = new BasicX509Credential();
            publicCredential.setPublicKey(publicKey);
            
        } catch (CertificateException ex) {
            logger.error("Error retrieving the signing cert: " + ex.getMessage());
            return null;

        } catch (FileNotFoundException ex) {
            logger.error("Error retrieving the signing cert: " + ex.getMessage());
            return null;
            
        } catch (InvalidKeySpecException ex) {
            logger.error("Error retrieving the signing cert: " + ex.getMessage());
            return null;
            
        } catch (NoSuchAlgorithmException ex) {
            logger.error("Error retrieving the signing cert: " + ex.getMessage());
            return null;
        }

        return publicCredential;
    }

}
