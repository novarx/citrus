/*
 * Copyright 2006-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.consol.citrus.endpoint.resolver;

import com.consol.citrus.channel.ChannelEndpoint;
import com.consol.citrus.channel.ChannelEndpointComponent;
import com.consol.citrus.endpoint.Endpoint;
import com.consol.citrus.endpoint.EndpointComponent;
import com.consol.citrus.exceptions.CitrusRuntimeException;
import com.consol.citrus.jms.JmsEndpoint;
import org.easymock.EasyMock;
import org.springframework.context.ApplicationContext;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.jms.ConnectionFactory;
import java.util.*;

import static org.easymock.EasyMock.*;

/**
 * @author Christoph Deppisch
 */
public class DefaultEndpointResolverTest {

    private ApplicationContext applicationContext = EasyMock.createMock(ApplicationContext.class);

    @Test
    public void testResolveDirectEndpoint() throws Exception {
        reset(applicationContext);

        expect(applicationContext.getBeansOfType(EndpointComponent.class)).andReturn(Collections.<String, EndpointComponent>emptyMap()).once();
        expect(applicationContext.getBean("myEndpoint", Endpoint.class)).andReturn(EasyMock.createMock(Endpoint.class)).once();

        replay(applicationContext);

        DefaultEndpointResolver resolver = new DefaultEndpointResolver(applicationContext);
        Endpoint endpoint = resolver.resolve("myEndpoint");

        Assert.assertNotNull(endpoint);

        verify(applicationContext);
    }

    @Test
    public void testResolveJmsEndpoint() throws Exception {
        reset(applicationContext);

        expect(applicationContext.getBeansOfType(EndpointComponent.class)).andReturn(Collections.<String, EndpointComponent>emptyMap()).once();
        expect(applicationContext.containsBean("connectionFactory")).andReturn(true).once();
        expect(applicationContext.getBean("connectionFactory", ConnectionFactory.class)).andReturn(EasyMock.createMock(ConnectionFactory.class)).once();

        replay(applicationContext);

        DefaultEndpointResolver resolver = new DefaultEndpointResolver(applicationContext);
        Endpoint endpoint = resolver.resolve("jms:Sample.Queue.Name");

        Assert.assertEquals(endpoint.getClass(), JmsEndpoint.class);
        Assert.assertEquals(((JmsEndpoint)endpoint).getEndpointConfiguration().getDestinationName(), "Sample.Queue.Name");

        verify(applicationContext);
    }

    @Test
    public void testResolveChannelEndpoint() throws Exception {
        reset(applicationContext);
        expect(applicationContext.getBeansOfType(EndpointComponent.class)).andReturn(Collections.<String, EndpointComponent>emptyMap()).once();
        replay(applicationContext);

        DefaultEndpointResolver resolver = new DefaultEndpointResolver(applicationContext);
        Endpoint endpoint = resolver.resolve("channel:channel.name");

        Assert.assertEquals(endpoint.getClass(), ChannelEndpoint.class);
        Assert.assertEquals(((ChannelEndpoint)endpoint).getEndpointConfiguration().getChannelName(), "channel.name");

        verify(applicationContext);
    }

    @Test
    public void testResolveCustomEndpoint() throws Exception {
        Map<String, EndpointComponent> components = new HashMap<String, EndpointComponent>();
        components.put("custom", new ChannelEndpointComponent());

        reset(applicationContext);
        expect(applicationContext.getBeansOfType(EndpointComponent.class)).andReturn(components).once();
        replay(applicationContext);

        DefaultEndpointResolver resolver = new DefaultEndpointResolver(applicationContext);
        Endpoint endpoint = resolver.resolve("custom:custom.channel");

        Assert.assertEquals(endpoint.getClass(), ChannelEndpoint.class);
        Assert.assertEquals(((ChannelEndpoint)endpoint).getEndpointConfiguration().getChannelName(), "custom.channel");

        verify(applicationContext);
    }

    @Test
    public void testOverwriteEndpointComponent() throws Exception {
        Map<String, EndpointComponent> components = new HashMap<String, EndpointComponent>();
        components.put("jms", new ChannelEndpointComponent());

        reset(applicationContext);
        expect(applicationContext.getBeansOfType(EndpointComponent.class)).andReturn(components).once();
        replay(applicationContext);

        DefaultEndpointResolver resolver = new DefaultEndpointResolver(applicationContext);
        Endpoint endpoint = resolver.resolve("jms:custom.channel");

        Assert.assertEquals(endpoint.getClass(), ChannelEndpoint.class);
        Assert.assertEquals(((ChannelEndpoint)endpoint).getEndpointConfiguration().getChannelName(), "custom.channel");

        verify(applicationContext);
    }

    @Test
    public void testResolveUnknownEndpointComponent() throws Exception {
        reset(applicationContext);
        expect(applicationContext.getBeansOfType(EndpointComponent.class)).andReturn(Collections.<String, EndpointComponent>emptyMap()).once();
        replay(applicationContext);

        DefaultEndpointResolver resolver = new DefaultEndpointResolver(applicationContext);
        try {
            resolver.resolve("unknown:unknown");
            Assert.fail("Missing exception due to unknown endpoint component");
        } catch (CitrusRuntimeException e) {
            Assert.assertTrue(e.getMessage().startsWith("Unable to resolve endpoint component"));
            verify(applicationContext);
        }
    }

    @Test
    public void testResolveInvalidEndpointUri() throws Exception {
        reset(applicationContext);
        expect(applicationContext.getBeansOfType(EndpointComponent.class)).andReturn(Collections.<String, EndpointComponent>emptyMap()).once();
        replay(applicationContext);

        DefaultEndpointResolver resolver = new DefaultEndpointResolver(applicationContext);
        try {
            resolver.resolve("jms:");
            Assert.fail("Missing exception due to invalid endpoint uri");
        } catch (CitrusRuntimeException e) {
            Assert.assertTrue(e.getMessage().startsWith("Invalid endpoint uri"));
            verify(applicationContext);
        }
    }
}
