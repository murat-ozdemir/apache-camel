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
import org.apache.camel.ContextTestSupport;
import org.apache.camel.Service;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultCamelContextStopFailureTest extends ContextTestSupport {

    private static String stopOrder;

    @Override
    protected CamelContext createCamelContext() throws Exception {
        CamelContext context = super.createCamelContext();
        context.addService(new MyService("A", false));
        context.addService(new MyService("B", true));
        context.addService(new MyService("C", false));
        return context;
    }

    @Test
    public void testStopWithFailure() throws Exception {
        stopOrder = "";

        context.stop();

        assertEquals("CBA", stopOrder);
    }

    private static final class MyService implements Service {

        private final String name;
        private final boolean fail;

        private MyService(String name, boolean fail) {
            this.name = name;
            this.fail = fail;
        }

        @Override
        public void start() {
        }

        @Override
        public void stop() {
            stopOrder = stopOrder + name;

            if (fail) {
                throw new IllegalArgumentException("Fail " + name);
            }
        }
    }
}
