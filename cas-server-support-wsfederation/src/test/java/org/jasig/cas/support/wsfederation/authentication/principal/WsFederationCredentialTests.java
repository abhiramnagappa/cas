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
package org.jasig.cas.support.wsfederation.authentication.principal;

import java.util.HashMap;
import org.jasig.cas.support.wsfederation.WsFederationUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml1.core.impl.AssertionImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author John Gasper
 * @since 3.4.8
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:/applicationContext.xml")
public class WsFederationCredentialTests {

    @Autowired
    HashMap<String,String> testTokens;
    
    WsFederationCredential standardCred;

    @Before
    public void setUp() {
        standardCred = new WsFederationCredential();
        standardCred.setNotBefore(new DateTime().withZone(DateTimeZone.UTC));
        standardCred.setNotOnOrAfter(new DateTime().withZone(DateTimeZone.UTC).plusHours(1));
        standardCred.setIssuedOn(new DateTime().withZone(DateTimeZone.UTC));
        standardCred.setIssuer("http://example.com/adfs/services/trust");
        standardCred.setAudience("urn:federation:Ewucas");
        standardCred.setId("_8010ecc3-8cd1-47c1-b349-1fc7e25f19cb");
        standardCred.setRetrievedOn(new DateTime().withZone(DateTimeZone.UTC).plusSeconds(1));
    }
    
    @Test
    public void testToString() {
        String wresult = testTokens.get("goodToken");
        AssertionImpl assertion = WsFederationUtils.parseTokenString(wresult);
        WsFederationCredential instance = WsFederationUtils.createCredentialFromToken(assertion);
        String expResult = 
                "ID: _8010ecc3-8cd1-47c1-b349-1fc7e25f19cb\n" +
                "Issuer: http://login-test-env.ewu.edu/adfs/services/trust\n" +
                "Audience: urn:federation:Ewucas\n" +
                "Audience Method: urn:oasis:names:tc:SAML:1.0:am:password\n" +
                "Issued On: 2012-10-16T18:52:09.284Z\n" + 
                "Valid After: 2012-10-16T18:52:09.268Z\n" + 
                "Valid Before: 2012-10-16T19:52:09.268Z\n" + 
                "Attributes:\n" + 
                "  emailaddress: jgasper@mailtest.ewu.edu\n" + 
                "  upn: jgasper@mailtest.ewu.edu\n" + 
                "  givenname: John\n" + 
                "  surname: Gasper\n" + 
                "  telephone: (509) 359-6419\n" + 
                "  Group: [easterntest\\Domain Users, easterntest\\CRS-AAST301-75-200940, easterntest\\DEPT-IS-DC]\n";
        String result = instance.toString();
        assertEquals("toString() not equal", expResult,result);
    }

    @Test
    public void testIsValidAllGood() throws Exception {
        boolean result = standardCred.isValid("urn:federation:Ewucas", "http://example.com/adfs/services/trust", 2000);
        assertTrue("testIsValidAllGood() - True", result);
    }

    @Test
    public void testIsValidBadAudience() throws Exception {
        standardCred.setAudience("urn:NotUs");
        boolean result = standardCred.isValid("urn:federation:Ewucas", "http://example.com/adfs/services/trust", 2000);
        assertFalse("testIsValidBadAudeience() - False", result);
    }
    
    @Test
    public void testIsValidBadIssuer() throws Exception {
        standardCred.setIssuer("urn:NotThem");
        
        boolean result = standardCred.isValid("urn:federation:Ewucas", "http://example.com/adfs/services/trust", 2000);
        assertFalse("testIsValidBadIssuer() - False", result);
    }
    
    @Test
    public void testIsValidEarlyToken() throws Exception {
        standardCred.setNotBefore(new DateTime().withZone(DateTimeZone.UTC).plusDays(1));
        standardCred.setNotOnOrAfter(new DateTime().withZone(DateTimeZone.UTC).plusHours(1).plusDays(1));
        standardCred.setIssuedOn(new DateTime().withZone(DateTimeZone.UTC).plusDays(1));
        
        boolean result = standardCred.isValid("urn:federation:Ewucas", "http://example.com/adfs/services/trust", 2000);
        assertFalse("testIsValidEarlyToken() - False", result);
    }
    
    @Test
    public void testIsValidOldToken() throws Exception {
        standardCred.setNotBefore(new DateTime().withZone(DateTimeZone.UTC).minusDays(1));
        standardCred.setNotOnOrAfter(new DateTime().withZone(DateTimeZone.UTC).plusHours(1).minusDays(1));
        standardCred.setIssuedOn(new DateTime().withZone(DateTimeZone.UTC).minusDays(1));
        
        boolean result = standardCred.isValid("urn:federation:Ewucas", "http://example.com/adfs/services/trust", 2000);
        assertFalse("testIsValidOldToken() - False", result);
    }
    
    @Test
    public void testIsValidExpiredIssuedOn() throws Exception {
        standardCred.setIssuedOn(new DateTime().withZone(DateTimeZone.UTC).minusSeconds(3));
        
        boolean result = standardCred.isValid("urn:federation:Ewucas", "http://example.com/adfs/services/trust", 2000);
        assertFalse("testIsValidOldToken() - False", result);
    }
    
    public void setTestTokens(HashMap<String, String> testTokens) {
        this.testTokens = testTokens;
    }
}
