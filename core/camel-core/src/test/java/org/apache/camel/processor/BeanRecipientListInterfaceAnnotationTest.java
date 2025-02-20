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
package org.apache.camel.processor;

import java.util.concurrent.atomic.AtomicInteger;

import org.apache.camel.spi.Registry;

public class BeanRecipientListInterfaceAnnotationTest extends BeanRecipientListTest {
    @Override
    protected void checkBean() throws Exception {
        // do nothing here
    }

    @Override
    protected Registry createCamelRegistry() throws Exception {
        Registry answer = super.createCamelRegistry();
        answer.bind("myBean", new MyBean());
        return answer;
    }

    interface Route {
        @org.apache.camel.RecipientList
        String[] route(String body);
    }

    public static class MyBean implements Route {
        private static final AtomicInteger counter = new AtomicInteger();
        private final int id;

        public MyBean() {
            id = counter.incrementAndGet();
        }

        @Override
        public String toString() {
            return "MyBean:" + id;
        }

        @Override
        public String[] route(String body) {
            return new String[] { "mock:a", "mock:b" };
        }
    }

}
