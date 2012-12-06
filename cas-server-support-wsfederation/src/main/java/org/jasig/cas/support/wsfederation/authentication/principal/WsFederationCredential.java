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

import java.util.Map;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents the basic elements of the WsFederation/SAML1 token.
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public class WsFederationCredential {
    private static final Logger logger = LoggerFactory.getLogger(WsFederationCredential.class);
    
    private String issuer,
           audience,
           authenticationMethod,
           id;
    
    private DateTime
            notBefore,
            notOnOrAfter,
            issuedOn,
            retrievedOn;
    
    Map<String, Object> attributes;

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
    public String getIssuer() {
        return this.issuer;
    }
    
    public void setAudience(String audience) {
        this.audience = audience;
    }
    public String getAudience() {
        return this.audience;
    }
    
    public void setAuthenticationMethod(String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }
    public String getAuthenticationMethod() {
        return this.authenticationMethod;
    }

    public void setId(String id) {
        this.id = id;
    }
    public String getId() {
        return this.id;
    }
    
    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }
    
    public void setNotBefore(DateTime notBefore) {
        this.notBefore = notBefore;
    }
    public DateTime getNotBefore() {
        return this.notBefore;
    }
    
    public void setIssuedOn(DateTime issuedOn) {
        this.issuedOn = issuedOn;
    }
    public DateTime getIssuedOn() {
        return this.issuedOn;
    }
    
    public void setNotOnOrAfter(DateTime notOnOrAfter) {
        this.notOnOrAfter = notOnOrAfter;
    }
    public DateTime getNotOnOrAfter() {
        return this.notOnOrAfter;
    }

    public void setRetrievedOn(DateTime retrievedOn) {
        this.retrievedOn = retrievedOn;
    }
    public DateTime getRetrievedOn() {
        return this.retrievedOn;
    }
    
    @Override
    public String toString() {
        String template = "ID: %s\nIssuer: %s\nAudience: %s\nAudience Method: %s\nIssued On: %s\nValid After: %s\nValid Before: %s\nAttributes:\n%s";
        
        String attributeList = "";
        
        for ( String attr : this.attributes.keySet() ) {
            attributeList += "  " + attr + ": " + (attributes.get(attr)).toString() + "\n";
        }
                    
        return String.format(template, this.id, this.issuer, this.audience, this.authenticationMethod,
                this.issuedOn.toString(), this.notBefore.toString(), this.notOnOrAfter.toString(), attributeList);
    }
    
    public boolean isValid(String expectedAudience, String expectedIssuer, int timeDrift) {
        //check the audience
        if ( !this.getAudience().equalsIgnoreCase(expectedAudience) ) {
            logger.warn(String.format("isValid: Audience is not valid. (%s)", this.getAudience()));
            return false;
        }
        
        //check the issuer
        if ( !this.getIssuer().equalsIgnoreCase(expectedIssuer) ) {
            logger.warn(String.format("isValid: Issuer is not valid. (%s)", this.getIssuer()));
            return false;
        }

        /*//Checking for early usage
        if ( this.getRetrievedOn().isBefore(this.getNotBefore()) ) {
            logger.warn(String.format("isValid: Ticket is too early."));
            return false;
        }
        */
        //Checking for late usage
        if ( this.getRetrievedOn().isAfter(this.getNotOnOrAfter()) ) {
            logger.warn(String.format("isValid: Ticket is too late."));
            return false;
        }
        
        //Check that the ticket was recently issued.
        if ( this.getIssuedOn().isBefore(this.getRetrievedOn().minusMillis(timeDrift)) ||
             this.getIssuedOn().isAfter(this.getRetrievedOn().plusMillis(timeDrift)) ) {
            logger.warn(String.format("isValid: Ticket outside of drift."));
            return false;
        }
        logger.debug("isValid: credential is valid."); 
        return true;
    }
}
