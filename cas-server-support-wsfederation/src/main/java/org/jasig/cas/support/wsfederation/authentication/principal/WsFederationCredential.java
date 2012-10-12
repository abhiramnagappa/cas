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

/**
 * This class represents the basic elements of the WsFederation/SAML1 token.
 * 
 * @author John Gasper
 * @since 3.5.1
 */
public class WsFederationCredential {
    
    String issuer,
           audience,
           authenticationMethod,
           id;
    
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
    public String getaudience() {
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
    
    //TODO: implement ToString method
    //TODO: implement Validate method
}
