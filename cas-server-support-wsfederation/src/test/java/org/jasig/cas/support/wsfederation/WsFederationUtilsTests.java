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

import java.util.HashMap;
import org.jasig.cas.support.wsfederation.authentication.principal.WsFederationCredential;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml1.core.impl.AssertionImpl;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author John Gasper
 * @since 3.5.1
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:/applicationContext.xml")
public class WsFederationUtilsTests {
    
    @Autowired
    WsFederationConfiguration wsFedConfig;
    
    @Autowired
    HashMap<String,String> testTokens;
    
    @Test
    public void testParseTokenString() throws Exception {
        String wresult = testTokens.get("goodToken");
        AssertionImpl result = WsFederationUtils.parseTokenString(wresult);
        
        assertNotNull("testParseTokenString() - Not null", result);
    }

    @Test
    public void testCreateCredentialFromToken() throws Exception {
        String wresult = testTokens.get("goodToken");;
        AssertionImpl assertion = WsFederationUtils.parseTokenString(wresult);
        
        WsFederationCredential expResult = new WsFederationCredential();
        expResult.setIssuedOn(new DateTime("2012-10-16T18:52:09.284Z").withZone(DateTimeZone.UTC));
        expResult.setNotBefore(new DateTime("2012-10-16T18:52:09.268Z").withZone(DateTimeZone.UTC));
        expResult.setNotOnOrAfter(new DateTime("2012-10-16T19:52:09.268Z").withZone(DateTimeZone.UTC));
        expResult.setIssuer("http://login-test-env.ewu.edu/adfs/services/trust");
        expResult.setAudience("urn:federation:Ewucas");
        expResult.setId("_8010ecc3-8cd1-47c1-b349-1fc7e25f19cb");
        
        WsFederationCredential result = WsFederationUtils.createCredentialFromToken(assertion);
        
        assertNotNull("testCreateCredentialFromToken() - Not Null", result);
        assertEquals("testCreateCredentialFromToken() - IssuedOn", expResult.getIssuedOn(), result.getIssuedOn());
        assertEquals("testCreateCredentialFromToken() - NotBefore", expResult.getNotBefore(), result.getNotBefore());
        assertEquals("testCreateCredentialFromToken() - NotOnOrAfter", expResult.getNotOnOrAfter(), result.getNotOnOrAfter());
        assertEquals("testCreateCredentialFromToken() - Issuer", expResult.getIssuer(), result.getIssuer());
        assertEquals("testCreateCredentialFromToken() - Audience", expResult.getAudience(), result.getAudience());
        assertEquals("testCreateCredentialFromToken() - Id", expResult.getId(), result.getId());
    }
     
    @Test
    public void testGetSigningCredential() throws Exception {
        BasicX509Credential result = WsFederationUtils.getSigningCredential(wsFedConfig.getSigningCertificateFiles().get(0));
        assertNotNull("testGetSigningCredential() - Not Null", result);        
    }
        
    @Test
    public void testValidateSignatureGoodToken() throws Exception {
        String wresult = testTokens.get("goodToken");
        AssertionImpl assertion = WsFederationUtils.parseTokenString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, wsFedConfig.getSigningCertificates());
        assertTrue("testValidateSignatureGoodToken() - True", result);
    }

    @Test
    public void testValidateSignatureModifiedAttribute() throws Exception {
        String wresult = testTokens.get("badTokenModifiedAttribute");
        AssertionImpl assertion = WsFederationUtils.parseTokenString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, wsFedConfig.getSigningCertificates());
        assertFalse("testValidateSignatureModifiedAttribute() - False", result);
    }

    @Test
    public void testValidateSignatureModifiedKey() throws Exception {
        String wresult = testTokens.get("badTokenModifiedKey");
        AssertionImpl assertion = WsFederationUtils.parseTokenString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, wsFedConfig.getSigningCertificates());
        assertFalse("testValidateSignatureModifiedKey() - False", result);
    }

    @Test
    public void testValidateSignatureModifiedSignature() throws Exception {
        String wresult = testTokens.get("badTokenModifiedSignature");
        AssertionImpl assertion = WsFederationUtils.parseTokenString(wresult);
        boolean result = WsFederationUtils.validateSignature(assertion, wsFedConfig.getSigningCertificates());
        assertFalse("testValidateSignatureModifiedSignature() - False", result);
    }


    public void setWsFedConfig(WsFederationConfiguration config) {
        this.wsFedConfig = config;
    }
    
    public void setTestTokens(HashMap<String, String> testTokens) {
        this.testTokens = testTokens;
    }

}
