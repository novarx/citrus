package com.consol.citrus.config.xml;

import java.util.Map;

import com.consol.citrus.json.JsonSchemaRepository;
import com.consol.citrus.json.schema.SimpleJsonSchema;
import com.consol.citrus.testng.AbstractBeanDefinitionParserTest;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author Christoph Deppisch
 */
public class JsonSchemaRepositoryParserTest extends AbstractBeanDefinitionParserTest {

    @Test
    public void testJsonSchemaRepositoryParser() {
        //GIVEN

        //WHEN
        Map<String, JsonSchemaRepository> schemaRepositories = beanDefinitionContext.getBeansOfType(JsonSchemaRepository.class);

        //THEN
        Assert.assertEquals(schemaRepositories.size(), 2);

        // 1st schema repository
        JsonSchemaRepository schemaRepository = schemaRepositories.get("jsonSchemaRepository1");
        Assert.assertNotNull(schemaRepository.getSchemas());
        Assert.assertEquals(schemaRepository.getSchemas().size(), 2);
        Assert.assertEquals(schemaRepository.getSchemas().get(0).getClass(), SimpleJsonSchema.class);
        Assert.assertEquals(schemaRepository.getSchemas().get(1).getClass(), SimpleJsonSchema.class);
        Assert.assertNotNull(schemaRepository.getLocations());
        Assert.assertEquals(schemaRepository.getLocations().size(), 0);

        // 2nd schema repository
        schemaRepository = schemaRepositories.get("jsonSchemaRepository2");
        Assert.assertNotNull(schemaRepository.getSchemas());
        Assert.assertEquals(schemaRepository.getSchemas().size(), 2);
        Assert.assertNotNull(schemaRepository.getLocations());
        Assert.assertEquals(schemaRepository.getLocations().size(), 1);
        Assert.assertEquals(schemaRepository.getLocations().get(0), "classpath:com/consol/citrus/validation/*");

        Assert.assertTrue(beanDefinitionContext.containsBean("jsonSchema1"));
        Assert.assertTrue(beanDefinitionContext.containsBean("jsonSchema2"));
    }
}
