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
import java.util.Map;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author John Gasper
 * @since 3.5.1
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:/applicationContext.xml")
public class WsFederationAttributeMutatorTests {
    
    public WsFederationAttributeMutatorTests() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of modifyAttributes method, of class WsFederationAttributeMutator.
     */
    @Test
    public void testModifyAttributes() {
        Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("upn", "test@example.com");
        
        WsFederationAttributeMutator instance = new WsFederationAttributeMutatorImpl();
        instance.modifyAttributes(attributes);
        assertTrue("testModifyAttributes() - true", attributes.containsKey("test"));
        assertTrue("testModifyAttributes() - true", attributes.get("test").toString().equalsIgnoreCase("test"));
        assertTrue("testModifyAttributes() - true", attributes.containsKey("upn"));
        assertTrue("testModifyAttributes() - true", attributes.get("upn").toString().equalsIgnoreCase("test"));
    }

    public class WsFederationAttributeMutatorImpl implements WsFederationAttributeMutator {

        public void modifyAttributes(Map<String, Object> attributes) {
            attributes.put("test", "test");
            attributes.put("upn", "test");
        }
    }
}
