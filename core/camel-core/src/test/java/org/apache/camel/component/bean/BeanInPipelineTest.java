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
package org.apache.camel.component.bean;

import org.apache.camel.ContextTestSupport;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.spi.Registry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit test to demonstrate beans in pipelines.
 */
public class BeanInPipelineTest extends ContextTestSupport {

    @Test
    public void testBeanInPipeline() throws Exception {
        Object response = template.requestBody("direct:start", "Start:");
        assertEquals("Start:onetwothree", response);
    }

    @Override
    protected Registry createCamelRegistry() throws Exception {
        Registry answer = super.createCamelRegistry();
        answer.bind("one", new MyBean("one"));
        answer.bind("two", new MyBean("two"));
        answer.bind("three", new MyBean("three"));
        return answer;
    }

    @Override
    protected RouteBuilder createRouteBuilder() throws Exception {
        return new RouteBuilder() {
            public void configure() throws Exception {
                from("direct:start").pipeline("bean:one", "bean:two", "log:x", "log:y", "bean:three");
            }
        };
    }

    public static class MyBean {

        private final String postfix;

        public MyBean(String postfix) {
            this.postfix = postfix;
        }

        public String doSomething(String body) {
            return body + postfix;
        }
    }

}
