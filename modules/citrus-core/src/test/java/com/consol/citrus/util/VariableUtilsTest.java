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

package com.consol.citrus.util;

import javax.script.ScriptException;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.consol.citrus.exceptions.CitrusRuntimeException;
import com.consol.citrus.testng.AbstractBaseTest;
import com.consol.citrus.variable.VariableUtils;

/**
 * @author Jan Lipphaus
 */
public class VariableUtilsTest extends AbstractBaseTest {
	
	private String validGroovyScript = "a = 1";
	private String groovyScriptResult = "1";
	private String invalidGroovyScript = "a";
	private String validScriptEngine = "groovy";
	private String invalidScriptEngine = "invalidScriptEngine";
	
	/**
	 * Test for correct return with valid script
	 */
	@Test
	public void testValidScript() {
		String result = VariableUtils.getValueFromScript(validScriptEngine, validGroovyScript);
		Assert.assertEquals(result, groovyScriptResult);
	}
	
	/**
	 * Test for correct exception with invalid script
	 */
	@Test
	public void testInvalidScript() {
		try {
		    VariableUtils.getValueFromScript(validScriptEngine, invalidGroovyScript);
		} catch (CitrusRuntimeException e) {
			Assert.assertTrue(e.getCause() instanceof ScriptException);
			return;
		}
		
		Assert.fail("Missing CitrusRuntimeException because of invalid groovy script");
	}
	
	/**
	 * Test for correct exception with invalid script engine
	 */
	@Test
	public void testInvalidScriptEngine() {
		try {
		    VariableUtils.getValueFromScript(invalidScriptEngine, validGroovyScript);
		} catch (CitrusRuntimeException e) {
			Assert.assertTrue(e.getMessage().contains(invalidScriptEngine));
			return;
		}
		
		Assert.fail("Missing CitrusRuntimeException because of invalid script engine");
	}
}
