/*
 * Copyright 2022 the original author or authors.
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.consol.citrus.xml;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementRefs;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.consol.citrus.TestActionBuilder;
import com.consol.citrus.exceptions.CitrusRuntimeException;
import com.consol.citrus.xml.actions.Action;
import com.consol.citrus.xml.actions.ApplyTemplate;
import com.consol.citrus.xml.actions.CreateVariables;
import com.consol.citrus.xml.actions.Echo;
import com.consol.citrus.xml.actions.ExpectTimeout;
import com.consol.citrus.xml.actions.Fail;
import com.consol.citrus.xml.actions.LoadProperties;
import com.consol.citrus.xml.actions.Print;
import com.consol.citrus.xml.actions.PurgeEndpoint;
import com.consol.citrus.xml.actions.Receive;
import com.consol.citrus.xml.actions.Sleep;
import com.consol.citrus.xml.actions.Start;
import com.consol.citrus.xml.actions.Stop;
import com.consol.citrus.xml.actions.StopTime;
import com.consol.citrus.xml.actions.StopTimer;
import com.consol.citrus.xml.actions.TraceVariables;
import com.consol.citrus.xml.actions.Transform;
import com.consol.citrus.xml.actions.XmlTestActionBuilder;
import com.consol.citrus.xml.container.Assert;
import com.consol.citrus.xml.container.Async;
import com.consol.citrus.xml.container.Catch;
import com.consol.citrus.xml.container.Conditional;
import com.consol.citrus.xml.container.Iterate;
import com.consol.citrus.xml.container.Parallel;
import com.consol.citrus.xml.container.Repeat;
import com.consol.citrus.xml.container.RepeatOnError;
import com.consol.citrus.xml.container.Sequential;
import com.consol.citrus.xml.container.Timer;
import com.consol.citrus.xml.container.WaitFor;
import org.w3c.dom.Node;

/**
 * @author Christoph Deppisch
 */
public class TestActions {

    /** Unmarshaller cache filled with instances created for custom action Xml element refs */
    private static final Map<String, Unmarshaller> UNMARSHALLER_CACHE = new HashMap<>();

    @XmlElementRefs({
            @XmlElementRef(name = "action", type = Action.class, required = false),
            @XmlElementRef(name = "echo", type = Echo.class, required = false),
            @XmlElementRef(name = "print", type = Print.class, required = false),
            @XmlElementRef(name = "sleep", type = Sleep.class, required = false),
            @XmlElementRef(name = "receive", type = Receive.class, required = false),
            @XmlElementRef(name = "create-variables", type = CreateVariables.class, required = false),
            @XmlElementRef(name = "load", type = LoadProperties.class, required = false),
            @XmlElementRef(name = "expect-timeout", type = ExpectTimeout.class, required = false),
            @XmlElementRef(name = "fail", type = Fail.class, required = false),
            @XmlElementRef(name = "iterate", type = Iterate.class, required = false),
            @XmlElementRef(name = "sequential", type = Sequential.class, required = false),
            @XmlElementRef(name = "parallel", type = Parallel.class, required = false),
            @XmlElementRef(name = "repeat", type = Repeat.class, required = false),
            @XmlElementRef(name = "repeat-on-error", type = RepeatOnError.class, required = false),
            @XmlElementRef(name = "conditional", type = Conditional.class, required = false),
            @XmlElementRef(name = "assert", type = Assert.class, required = false),
            @XmlElementRef(name = "catch", type = Catch.class, required = false),
            @XmlElementRef(name = "waitFor", type = WaitFor.class, required = false),
            @XmlElementRef(name = "async", type = Async.class, required = false),
            @XmlElementRef(name = "timer", type = Timer.class, required = false),
            @XmlElementRef(name = "stop-timer", type = StopTimer.class, required = false),
            @XmlElementRef(name = "stop-time", type = StopTime.class, required = false),
            @XmlElementRef(name = "start", type = Start.class, required = false),
            @XmlElementRef(name = "stop", type = Stop.class, required = false),
            @XmlElementRef(name = "trace-variables", type = TraceVariables.class, required = false),
            @XmlElementRef(name = "purge-endpoint", type = PurgeEndpoint.class, required = false),
            @XmlElementRef(name = "transform", type = Transform.class, required = false),
            @XmlElementRef(name = "apply-template", type = ApplyTemplate.class, required = false),
    })
    @XmlAnyElement(lax = true)
    private List<Object> actions;

    public List<Object> getActions() {
        return actions;
    }

    /**
     * Converts given XML actions to normal test action builder instances.
     * @return nested actions as test action builders.
     */
    public List<TestActionBuilder<?>> getActionBuilders() {
        List<TestActionBuilder<?>> builders = new ArrayList<>();

        for (Object object : getActions()) {
            Object action = object;

            if (object instanceof JAXBElement) {
                action = ((JAXBElement<?>) object).getValue();
            }

            if (object instanceof Node) {
                Node node = (Node) object;
                Optional<TestActionBuilder<?>> builder = XmlTestActionBuilder.lookup(node.getLocalName());
                if (builder.isPresent()) {
                    try {
                        Unmarshaller unmarshaller;
                        if (UNMARSHALLER_CACHE.containsKey(builder.get().getClass().getName())) {
                            unmarshaller = UNMARSHALLER_CACHE.get(builder.get().getClass().getName());
                        } else {
                            unmarshaller = JAXBContext.newInstance(builder.get().getClass()).createUnmarshaller();
                            UNMARSHALLER_CACHE.put(builder.get().getClass().getName(), unmarshaller);
                        }

                        action = unmarshaller.unmarshal(node, builder.get().getClass()).getValue();
                    } catch (JAXBException e) {
                        throw new CitrusRuntimeException("Failed to create XMLTestLoader instance", e);
                    }
                }
            }

            if (action instanceof TestActionBuilder<?>) {
                builders.add((TestActionBuilder<?>) action);
            }
        }

        return builders;
    }
}