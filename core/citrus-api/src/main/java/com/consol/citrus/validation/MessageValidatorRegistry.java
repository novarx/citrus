/*
 * Copyright 2006-2011 the original author or authors.
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

package com.consol.citrus.validation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.consol.citrus.exceptions.CitrusRuntimeException;
import com.consol.citrus.message.Message;
import com.consol.citrus.message.MessageType;
import com.consol.citrus.validation.context.ValidationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 * Simple registry holding all available message validator implementations. Test context can ask this registry for
 * matching validator implementation according to the message type (e.g. xml, json, csv, plaintext).
 *
 * Registry tries to find a matching validator for the message.
 *
 * @author Christoph Deppisch
 */
public class MessageValidatorRegistry {

    /** Logger */
    private static Logger log = LoggerFactory.getLogger(MessageValidatorRegistry.class);

    /** The default bean id in Spring application context*/
    public static final String BEAN_NAME = "citrusMessageValidatorRegistry";

    /** Message validator resource lookup path */
    public static final String RESOURCE_PATH = "META-INF/citrus/message/validator";

    /** Registered message validators */
    private Map<String, MessageValidator<? extends ValidationContext>> messageValidators = new LinkedHashMap<>();

    /**
     * Finds matching message validators for this message type.
     *
     * @param messageType the message type
     * @param message the message object
     * @return the list of matching message validators.
     */
    public List<MessageValidator<? extends ValidationContext>> findMessageValidators(String messageType, Message message) {
        List<MessageValidator<? extends ValidationContext>> matchingValidators = new ArrayList<>();

        for (MessageValidator<? extends ValidationContext> validator : messageValidators.values()) {
            if (validator.supportsMessageType(messageType, message)) {
                matchingValidators.add(validator);
            }
        }

        if (matchingValidators.isEmpty() || matchingValidators.stream().allMatch(validator -> DefaultMessageHeaderValidator.class.isAssignableFrom(validator.getClass()))) {
            // try to find fallback message validator for given message payload
            if (message.getPayload() instanceof String &&
                    StringUtils.hasText(message.getPayload(String.class))) {
                String payload = message.getPayload(String.class).trim();

                if (payload.startsWith("<") && !messageType.equals(MessageType.XML.name())) {
                    matchingValidators = findFallbackMessageValidators(MessageType.XML.name(), message);
                } else if ((payload.startsWith("{") || payload.startsWith("[")) && !messageType.equals(MessageType.JSON.name())) {
                    matchingValidators = findFallbackMessageValidators(MessageType.JSON.name(), message);
                } else if (!messageType.equals(MessageType.PLAINTEXT.name())) {
                    matchingValidators = findFallbackMessageValidators(MessageType.PLAINTEXT.name(), message);
                }
            }
        }

        if (matchingValidators.isEmpty() || matchingValidators.stream().allMatch(validator -> DefaultMessageHeaderValidator.class.isAssignableFrom(validator.getClass()))) {
            throw new CitrusRuntimeException("Could not find proper message validator for message type '" +
                    messageType + "', please define a capable message validator for this message type");
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("Found %s message validators for message type: %s", matchingValidators.size(), messageType));
        }

        return matchingValidators;
    }

    private List<MessageValidator<? extends ValidationContext>> findFallbackMessageValidators(String messageType, Message message) {
        List<MessageValidator<? extends ValidationContext>> matchingValidators = new ArrayList<>();

        for (MessageValidator<? extends ValidationContext> validator : messageValidators.values()) {
            if (validator.supportsMessageType(messageType, message)) {
                matchingValidators.add(validator);
            }
        }

        return matchingValidators;
    }

    /**
     * Sets available message validator implementations.
     * @param messageValidators the messageValidators to set
     */
    public void setMessageValidators(
            Map<String, MessageValidator<? extends ValidationContext>> messageValidators) {
        this.messageValidators = messageValidators;
    }

    /**
     * Gets the message validators.
     * @return
     */
    public Map<String, MessageValidator<? extends ValidationContext>> getMessageValidators() {
        return messageValidators;
    }

    /**
     * Gets the default message header validator.
     * @return
     */
    public DefaultMessageHeaderValidator getDefaultMessageHeaderValidator() {
        return messageValidators.values()
                .stream()
                .filter(validator -> DefaultMessageHeaderValidator.class.isAssignableFrom(validator.getClass()))
                .map(DefaultMessageHeaderValidator.class::cast)
                .findFirst()
                .orElse(null);
    }
}
