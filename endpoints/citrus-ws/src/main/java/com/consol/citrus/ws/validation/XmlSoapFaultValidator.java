/*
 * Copyright 2006-2010 the original author or authors.
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

package com.consol.citrus.ws.validation;

import java.util.Collections;

import com.consol.citrus.context.TestContext;
import com.consol.citrus.exceptions.CitrusRuntimeException;
import com.consol.citrus.exceptions.ValidationException;
import com.consol.citrus.message.DefaultMessage;
import com.consol.citrus.spi.ResourcePathTypeResolver;
import com.consol.citrus.spi.TypeResolver;
import com.consol.citrus.validation.MessageValidator;
import com.consol.citrus.validation.MessageValidatorRegistry;
import com.consol.citrus.validation.context.ValidationContext;
import com.consol.citrus.validation.xml.XmlMessageValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Soap fault validator implementation that delegates soap fault detail validation to default XML message validator
 * in order to support XML fault detail content validation.
 *
 * @author Christoph Deppisch
 */
public class XmlSoapFaultValidator extends AbstractFaultDetailValidator {

    /** Logger */
    private static Logger log = LoggerFactory.getLogger(XmlSoapFaultValidator.class);

    /** Xml message validator */
    private MessageValidator<? extends ValidationContext> messageValidator;

    /** Type resolver for message validator lookup via resource path */
    private static final TypeResolver TYPE_RESOLVER = new ResourcePathTypeResolver(MessageValidatorRegistry.RESOURCE_PATH);

    public static final String DEFAULT_XML_MESSAGE_VALIDATOR = "defaultXmlMessageValidator";

    /**
     * Delegates to XML message validator for validation of fault detail.
     */
    @Override
    protected void validateFaultDetailString(String receivedDetailString, String controlDetailString,
            TestContext context, ValidationContext validationContext) throws ValidationException {
        XmlMessageValidationContext xmlMessageValidationContext;

        if (validationContext instanceof XmlMessageValidationContext) {
            xmlMessageValidationContext = (XmlMessageValidationContext) validationContext;
        } else {
            xmlMessageValidationContext = new XmlMessageValidationContext();
        }

        getMessageValidator(context).validateMessage(new DefaultMessage(receivedDetailString), new DefaultMessage(controlDetailString),
                context, Collections.singletonList(xmlMessageValidationContext));
    }

    /**
     * Find proper XML message validator. Uses several strategies to lookup default XML message validator. Caches found validator for
     * future usage once the lookup is done.
     * @param context
     * @return
     */
    private MessageValidator<? extends ValidationContext> getMessageValidator(TestContext context) {
        if (messageValidator != null) {
            return messageValidator;
        }

        // try to find xml message validator in registry
        messageValidator = context.getMessageValidatorRegistry().getMessageValidators().get(DEFAULT_XML_MESSAGE_VALIDATOR);

        if (messageValidator == null) {
            try {
                messageValidator = context.getReferenceResolver().resolve(DEFAULT_XML_MESSAGE_VALIDATOR, MessageValidator.class);
            } catch (CitrusRuntimeException e) {
                log.warn("Unable to find default XML message validator in message validator registry");
            }
        }

        if (messageValidator == null) {
            // try to find xml message validator via resource path lookup
            messageValidator = TYPE_RESOLVER.resolve("xml");
        }

        return messageValidator;
    }
}
