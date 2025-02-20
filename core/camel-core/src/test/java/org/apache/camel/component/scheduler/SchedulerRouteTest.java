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
package org.apache.camel.component.scheduler;

import java.util.concurrent.atomic.AtomicInteger;

import org.apache.camel.ContextTestSupport;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.spi.Registry;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SchedulerRouteTest extends ContextTestSupport {
    private static final Logger LOG = LoggerFactory.getLogger(SchedulerRouteTest.class);
    private final MyBean bean = new MyBean();

    @Test
    public void testSchedulerInvokesBeanMethod() throws Exception {
        MockEndpoint mock = getMockEndpoint("mock:result");
        mock.expectedMinimumMessageCount(2);

        assertMockEndpointsSatisfied();

        assertTrue(bean.counter.get() >= 2, "Should have fired 2 or more times was: " + bean.counter.get());
    }

    @Override
    protected RouteBuilder createRouteBuilder() throws Exception {
        return new RouteBuilder() {
            public void configure() {
                from("scheduler://foo?delay=100").log("Fired scheduler").to("bean:myBean", "mock:result");
            }
        };
    }

    @Override
    protected Registry createCamelRegistry() throws Exception {
        Registry answer = super.createCamelRegistry();
        answer.bind("myBean", bean);
        return answer;
    }

    public static class MyBean {
        public final AtomicInteger counter = new AtomicInteger();

        public void someMethod() {
            LOG.debug("Invoked someMethod()");
            counter.incrementAndGet();
        }
    }
}
