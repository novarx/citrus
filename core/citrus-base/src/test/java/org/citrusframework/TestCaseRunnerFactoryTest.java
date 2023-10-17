package org.citrusframework;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import org.citrusframework.context.TestContext;
import org.citrusframework.spi.ResourcePathTypeResolver;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestCaseRunnerFactoryTest {

    @Test
    public void testDefaultRunnerWithGivenContext()  {
        TestContext testContext = new TestContext();
        TestCaseRunner runner = TestCaseRunnerFactory.createRunner(testContext);
        assertEquals(runner.getClass(), DefaultTestCaseRunner.class);

        DefaultTestCaseRunner defaultTestCaseRunner = (DefaultTestCaseRunner) runner;
        assertEquals(defaultTestCaseRunner.getContext(), testContext);
        assertTrue(defaultTestCaseRunner.getTestCase() instanceof  DefaultTestCase);
    }

    @Test
    public void testDefaultRunnerWithGivenTestCaseAndContext()  {
        TestContext testContext = new TestContext();
        TestCase testCase = new DefaultTestCase();

        TestCaseRunner runner = TestCaseRunnerFactory.createRunner(testCase, testContext);
        assertEquals(runner.getClass(), DefaultTestCaseRunner.class);

        DefaultTestCaseRunner defaultTestCaseRunner = (DefaultTestCaseRunner) runner;
        assertEquals(defaultTestCaseRunner.getContext(), testContext);
        assertEquals(defaultTestCaseRunner.getTestCase(), testCase);
    }

    @Test
    public void testCustomRunnerGivenContext() {
        ResourcePathTypeResolver resolverMock = Mockito.mock(ResourcePathTypeResolver.class);

        Mockito.doReturn(new CustomTestCaseRunnerProvider()).when(resolverMock).resolve("custom");
        TestCaseRunnerFactory instance = (TestCaseRunnerFactory) ReflectionTestUtils.getField(
            TestCaseRunnerFactory.class,"INSTANCE");
        Assert.assertNotNull(instance);

        TestContext testContext = new TestContext();

        Object currentResolver = ReflectionTestUtils.getField(instance, "typeResolver");
        try {
            ReflectionTestUtils.setField(instance, "typeResolver", resolverMock);
            TestCaseRunner runner = TestCaseRunnerFactory.createRunner(testContext);

            assertEquals(runner.getClass(), CustomTestCaseRunner.class);

            CustomTestCaseRunner defaultTestCaseRunner = (CustomTestCaseRunner) runner;
            assertEquals(defaultTestCaseRunner.getContext(), testContext);

        } finally {
            ReflectionTestUtils.setField(instance, "typeResolver", currentResolver);
        }

    }

    @Test
    public void testCustomRunnerGivenTestCaseAndContext() {
        ResourcePathTypeResolver resolverMock = Mockito.mock(ResourcePathTypeResolver.class);

        Mockito.doReturn(new CustomTestCaseRunnerProvider()).when(resolverMock).resolve("custom");
        TestCaseRunnerFactory instance = (TestCaseRunnerFactory) ReflectionTestUtils.getField(
            TestCaseRunnerFactory.class,"INSTANCE");
        Assert.assertNotNull(instance);

        TestContext testContext = new TestContext();
        TestCase testCase = new DefaultTestCase();

        Object currentResolver = ReflectionTestUtils.getField(instance, "typeResolver");
        try {
            ReflectionTestUtils.setField(instance, "typeResolver", resolverMock);
            TestCaseRunner runner = TestCaseRunnerFactory.createRunner(testCase, testContext);

            assertEquals(runner.getClass(), CustomTestCaseRunner.class);

            CustomTestCaseRunner defaultTestCaseRunner = (CustomTestCaseRunner) runner;
            assertEquals(defaultTestCaseRunner.getContext(), testContext);
            assertEquals(defaultTestCaseRunner.getTestCase(), testCase);

        } finally {
            ReflectionTestUtils.setField(instance, "typeResolver", currentResolver);
        }

    }

    private static class CustomTestCaseRunnerProvider implements TestCaseRunnerProvider {

        @Override
        public TestCaseRunner createTestCaseRunner(TestCase testCase, TestContext context) {
            return new CustomTestCaseRunner(testCase, context);
        }

        @Override
        public TestCaseRunner createTestCaseRunner(TestContext context) {
            return new CustomTestCaseRunner(context);
        }
    }

    private static class CustomTestCaseRunner extends DefaultTestCaseRunner {

        public CustomTestCaseRunner(TestContext context) {
            super(context);
        }

        public CustomTestCaseRunner(TestCase testCase, TestContext context) {
            super(testCase, context);
        }
    }
}
