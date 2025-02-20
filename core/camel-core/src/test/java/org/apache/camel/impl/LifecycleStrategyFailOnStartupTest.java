/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.impl;

import org.apache.camel.CamelContext;
import org.apache.camel.TestSupport;
import org.apache.camel.VetoCamelContextStartException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class LifecycleStrategyFailOnStartupTest extends TestSupport {

    private final MyLifecycleStrategy dummy1 = new MyLifecycleStrategy();

    protected CamelContext createCamelContext() throws Exception {
        CamelContext context = new DefaultCamelContext();
        context.addLifecycleStrategy(dummy1);
        return context;
    }

    @Test
    public void testLifecycleStrategyFailOnStartup() throws Exception {
        CamelContext context = createCamelContext();
        Exception e = assertThrows(Exception.class, context::start, "Should have thrown exception");
        assertEquals("Forced", e.getMessage());
    }

    private static class MyLifecycleStrategy extends DummyLifecycleStrategy {

        @Override
        public void onContextStarting(CamelContext context) throws VetoCamelContextStartException {
            throw new IllegalArgumentException("Forced");
        }
    }

}
