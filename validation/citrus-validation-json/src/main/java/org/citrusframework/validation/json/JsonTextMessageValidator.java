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

package org.citrusframework.validation.json;

import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.ReadContext;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.citrusframework.context.TestContext;
import org.citrusframework.exceptions.CitrusRuntimeException;
import org.citrusframework.exceptions.ValidationException;
import org.citrusframework.json.JsonSchemaRepository;
import org.citrusframework.json.JsonSettings;
import org.citrusframework.message.Message;
import org.citrusframework.message.MessageType;
import org.citrusframework.util.MessageUtils;
import org.citrusframework.validation.AbstractMessageValidator;
import org.citrusframework.validation.json.schema.JsonSchemaValidation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;

import static java.util.Objects.requireNonNullElse;
import static org.citrusframework.CitrusSettings.IGNORE_PLACEHOLDER;
import static org.citrusframework.util.StringUtils.hasText;
import static org.citrusframework.validation.ValidationUtils.buildValueMismatchErrorMessage;
import static org.citrusframework.validation.ValidationUtils.buildValueToBeInCollectionErrorMessage;
import static org.citrusframework.validation.matcher.ValidationMatcherUtils.isValidationMatcherExpression;
import static org.citrusframework.validation.matcher.ValidationMatcherUtils.resolveValidationMatcher;

/**
 * This message validator implementation is able to validate two JSON text objects. The order of JSON entries can differ
 * as specified in JSON protocol. Tester defines an expected control JSON text with optional ignored entries.
 *
 * JSONArray as well as nested JSONObjects are supported, too.
 *
 * Validator offers two different modes to operate. By default strict mode is set and the validator will also check the exact amount of
 * control object fields to match. No additional fields in received JSON data structure will be accepted. In soft mode validator
 * allows additional fields in received JSON data structure so the control JSON object can be a partial subset.
 *
 * @author Christoph Deppisch
 */
public class JsonTextMessageValidator extends AbstractMessageValidator<JsonMessageValidationContext> {

    /** Should also check exact amount of object fields */
    private boolean strict = JsonSettings.isStrict();

    /** Permissive mode to use on the Json parser */
    private int permissiveMode = JsonSettings.getPermissiveMoe();

    /** Schema validator */
    private JsonSchemaValidation jsonSchemaValidation = new JsonSchemaValidation();

    @Override
    public void validateMessage(Message receivedMessage, Message controlMessage,
                                TestContext context, JsonMessageValidationContext validationContext) {
        if (controlMessage == null || controlMessage.getPayload() == null) {
            logger.debug("Skip message payload validation as no control message was defined");
            return;
        }

        logger.debug("Start JSON message validation ...");

        if (validationContext.isSchemaValidationEnabled()) {
            jsonSchemaValidation.validate(receivedMessage, context, validationContext);
        }

        String receivedJsonText = receivedMessage.getPayload(String.class);
        String controlJsonText = context.replaceDynamicContentInString(controlMessage.getPayload(String.class));

        try {
            if (!hasText(controlJsonText)) {
                logger.debug("Skip message payload validation as no control message was defined");
                return;
            } else {
                if (!hasText(receivedJsonText)) {
                    throw new ValidationException("Validation failed - " + "expected message contents, but received empty message!");
                }
            }

            JSONParser parser = new JSONParser(permissiveMode);

            Object receivedJson = parser.parse(receivedJsonText);
            ReadContext readContext = JsonPath.parse(receivedJson);
            Object controlJson = parser.parse(controlJsonText);
            if (receivedJson instanceof JSONObject) {
                validateJson(new JsonValidation("$.", (JSONObject) receivedJson, (JSONObject) controlJson, validationContext, context, readContext));
            } else if (receivedJson instanceof JSONArray) {
                JSONObject tempReceived = new JSONObject();
                tempReceived.put("array", receivedJson);
                JSONObject tempControl = new JSONObject();
                tempControl.put("array", controlJson);

                validateJson(new JsonValidation("$.", tempReceived, tempControl, validationContext, context, readContext));
            } else {
                throw new CitrusRuntimeException("Unsupported json type " + receivedJson.getClass());
            }
        } catch (IllegalArgumentException e) {
            throw new ValidationException(String.format("Failed to validate JSON text:%n%s", receivedJsonText), e);
        } catch (ParseException e) {
            throw new CitrusRuntimeException("Failed to parse JSON text", e);
        }

        logger.info("JSON message validation successful: All values OK");
    }

    /**
     * Find json schema repositories in test context.
     * @param context
     * @return
     */
    private List<JsonSchemaRepository> findSchemaRepositories(TestContext context) {
        return new ArrayList<>(context.getReferenceResolver().resolveAll(JsonSchemaRepository.class).values());
    }

    /**
     * Validates JSON text with comparison to expected control JSON object.
     * JSON entries can be ignored with ignore placeholder.
     */
    public void validateJson(JsonValidation jsonValidation) {
        if (strict) {
            if (jsonValidation.controlJson().size() != jsonValidation.receivedJson().size()) {
                throwValueMismatch("Number of JSON entries not equal for element: '" + jsonValidation.elementName() + "'", jsonValidation.controlJson().size(), jsonValidation.receivedJson().size());
            }
        }

        for (var controlEntry : jsonValidation.controlJson().entrySet().stream().map(JsonEntry::new).toList()) {
            Object receivedValue = jsonValidation.recivedValueFor(controlEntry);

            if (!jsonValidation.receivedJson().containsKey(controlEntry.name)) {
                throw new ValidationException("Missing JSON entry: + '" + controlEntry.name + "'");
            }

            if (controlEntry.value == null && receivedValue != null) {
                throwValueMismatch("Values not equal for entry: '" + controlEntry.name + "'", null, receivedValue);
            }

            if (isIgnoredByPlaceholderOrExpressionList(jsonValidation, controlEntry)) {
                continue;
            }

            validateJsonElement(jsonValidation, controlEntry);

            logger.debug("Validation successful for JSON entry '{}' ({})", controlEntry.name, controlEntry.value);
        }
    }

    private void validateJsonElement(JsonValidation jsonValidation, JsonEntry control) {
        Object receivedValue = jsonValidation.recivedValueFor(control);

        if (isValidationMatcherExpression(requireNonNullElse(control.stringValue(), ""))) {
            var stringValue = receivedValue == null ? null : receivedValue.toString();
            resolveValidationMatcher(control.name, stringValue, control.stringValue(), jsonValidation.context());
        } else if (control.value instanceof JSONObject) {
            validateJSONObject(jsonValidation.validationContext, jsonValidation.context, jsonValidation.readContext, (JSONObject) control.value, control.name, receivedValue);
        } else if (control.value instanceof JSONArray) {
            validateJSONArray(jsonValidation.validationContext, jsonValidation.context, jsonValidation.readContext, (JSONArray) control.value, control.name, receivedValue);
        } else {
            validateNativeType(control.value, control.name, receivedValue);
        }
    }

    private static void validateNativeType(Object controlValue, String controlKey, Object receivedValue) {
        if (controlValue != null && !controlValue.equals(receivedValue)) {
            throwValueMismatch("Values not equal for entry: '" + controlKey + "'", controlValue, receivedValue);
        }
    }

    private void validateJSONArray(JsonMessageValidationContext validationContext, TestContext context, ReadContext readContext, JSONArray controlValue, String controlKey, Object receivedValue) {
        if (!(receivedValue instanceof JSONArray)) {
            throwValueMismatch("Type mismatch for JSON entry '" + controlKey + "'", JSONArray.class.getSimpleName(), receivedValue.getClass().getSimpleName());
        }

        JSONArray jsonArrayReceived = (JSONArray) receivedValue;

        logger.debug("Validating JSONArray containing entries: {}", controlValue);

        if (strict) {
            if (controlValue.size() != jsonArrayReceived.size()) {
                throwValueMismatch("JSONArray size mismatch for JSON entry '" + controlKey + "'", controlValue.size(), jsonArrayReceived.size());
            }
        }
        for (Object controlItem : controlValue) {
            var potentialErrors = jsonArrayReceived.stream().map(recivedItem -> {
                try {
                    validateJsonArrayItem(validationContext, context, readContext, controlKey, controlItem, recivedItem);
                    return null;
                } catch (ValidationException e) {
                    return e;
                }
            }).toList();

            if (potentialErrors.stream().noneMatch(Objects::isNull)) {
                throw new ValidationException(buildValueToBeInCollectionErrorMessage(
                        "Value '%s' is not present".formatted(controlKey),
                        controlItem,
                        jsonArrayReceived
                ));
            }
        }
    }

    private void validateJsonArrayItem(JsonMessageValidationContext validationContext, TestContext context, ReadContext readContext, String controlKey, Object controlItem, Object recivedItem) {
        if (controlItem.getClass().isAssignableFrom(JSONObject.class)) {
            if (!recivedItem.getClass().isAssignableFrom(JSONObject.class)) {
                throwValueMismatch("Value types not equal for entry: '" + controlKey + "'", JSONObject.class.getName(), recivedItem.getClass().getName());
            }

            this.validateJson(new JsonValidation(controlKey, (JSONObject) recivedItem, (JSONObject) controlItem, validationContext, context, readContext));
        } else {
            validateNativeType(controlItem, controlKey, recivedItem);
        }
    }

    private void validateJSONObject(JsonMessageValidationContext validationContext, TestContext context, ReadContext readContext, JSONObject controlValue, String controlKey, Object receivedValue) {
        if (!(receivedValue instanceof JSONObject)) {
            throwValueMismatch("Type mismatch for JSON entry '" + controlKey + "'", JSONObject.class.getSimpleName(), receivedValue.getClass().getSimpleName());
        }

        this.validateJson(
                new JsonValidation(controlKey, (JSONObject) receivedValue, controlValue, validationContext, context, readContext));
    }

    private static void throwValueMismatch(String baseMessage, Object controlValue, Object receivedValue) {
        throw new ValidationException(buildValueMismatchErrorMessage(baseMessage, controlValue, receivedValue));
    }

    /**
     * Checks if given element node is either on ignore list or
     * contains @ignore@ tag inside control message
     */
    public boolean isIgnoredByPlaceholderOrExpressionList(JsonValidation jsonValidation, JsonEntry controlEntry) {
        String trimmedControlValue = requireNonNullElse(controlEntry.stringValue(), "").trim();

        Object receivedJson = jsonValidation.receivedJson().get(controlEntry.name);

        if (trimmedControlValue.equals(IGNORE_PLACEHOLDER)) {
            logger.debug("JSON entry: '{}' is ignored by placeholder '{}'", controlEntry.name, IGNORE_PLACEHOLDER);
            return true;
        }

        for (String jsonPathExpression : jsonValidation.validationContext.getIgnoreExpressions()) {
            Object foundEntry = jsonValidation.readContext.read(jsonPathExpression);

            if (foundEntry instanceof JSONArray foundJsonArray && foundJsonArray.contains(receivedJson)) {
                logger.debug("JSON entry: '{}' is ignored - skip value validation", controlEntry.name);
                return true;
            }

            if (foundEntry != null && foundEntry.equals(receivedJson)) {
                logger.debug("JSON entry: '{}' is ignored - skip value validation", controlEntry.name);
                return true;
            }
        }

        return false;
    }

    @Override
    protected Class<JsonMessageValidationContext> getRequiredValidationContextType() {
        return JsonMessageValidationContext.class;
    }

    @Override
    public boolean supportsMessageType(String messageType, Message message) {
        return messageType.equalsIgnoreCase(MessageType.JSON.name()) && MessageUtils.hasJsonPayload(message);
    }

    /**
     * Set the validator strict mode.
     *
     * @param strict
     */
    public void setStrict(boolean strict) {
        this.strict = strict;
    }

    /**
     * Set the validator strict mode.
     *
     * @param strict
     * @return this object for chaining
     */
    public JsonTextMessageValidator strict(boolean strict) {
        setStrict(strict);
        return this;
    }

    /**
     * Sets the json schema validation.
     *
     * @param jsonSchemaValidation
     */
    void setJsonSchemaValidation(JsonSchemaValidation jsonSchemaValidation) {
        this.jsonSchemaValidation = jsonSchemaValidation;
    }

    /**
     * Sets the json schema validation.
     *
     * @param jsonSchemaValidation
     * @return this object for chaining
     */
    public JsonTextMessageValidator jsonSchemaValidation(JsonSchemaValidation jsonSchemaValidation) {
        setJsonSchemaValidation(jsonSchemaValidation);
        return this;
    }

    /**
     * Sets the permissive mode.
     *
     * @param permissiveMode
     */
    public void setPermissiveMode(int permissiveMode) {
        this.permissiveMode = permissiveMode;
    }

    /**
     * Sets the permissive mode
     *
     * @param permissiveMode
     * @return this object for chaining
     */
    public JsonTextMessageValidator permissiveMode(int permissiveMode) {
        setPermissiveMode(permissiveMode);
        return this;
    }

    public static class JsonEntry {
        public final String name;
        public final Object value;

        public JsonEntry(Entry<String, Object> entry) {
            this.name = entry.getKey();
            this.value = entry.getValue();
        }

        public String stringValue() {
            return value == null ? null : value.toString();
        }
    }

    public record JsonValidation(
            String elementName,
            JSONObject receivedJson,
            JSONObject controlJson,
            JsonMessageValidationContext validationContext,
            TestContext context,
            ReadContext readContext
    ) {
        public Object recivedValueFor(JsonEntry controlEntry) {
            return receivedJson.get(controlEntry.name);
        }
    }

}
