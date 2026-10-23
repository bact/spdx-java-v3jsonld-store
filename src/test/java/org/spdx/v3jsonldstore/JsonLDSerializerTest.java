/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.TypedLiteral;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.SpdxConstantsV3;
import org.spdx.library.model.v3_0_1.core.Agent;
import org.spdx.library.model.v3_0_1.core.CreationInfo;
import org.spdx.library.model.v3_0_1.core.ExternalElement;
import org.spdx.library.model.v3_0_1.core.HashAlgorithm;
import org.spdx.library.model.v3_0_1.core.Person;
import org.spdx.library.model.v3_0_1.core.Relationship;
import org.spdx.library.model.v3_0_1.core.RelationshipType;
import org.spdx.library.model.v3_0_1.core.SpdxDocument;
import org.spdx.library.model.v3_0_1.security.CvssV3VulnAssessmentRelationship;
import org.spdx.library.model.v3_0_1.security.Vulnerability;
import org.spdx.library.model.v3_0_1.software.SpdxFile;
import org.spdx.library.model.v3_0_1.software.SpdxPackage;
import org.spdx.storage.IModelStore;
import org.spdx.storage.PropertyDescriptor;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.simple.InMemSpdxStore;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * @author Gary O'Neall
 */
public class JsonLDSerializerTest {

	static final String XSD_INTEGER = "http://www.w3.org/2001/XMLSchema#integer";
	static final String XSD_DOUBLE = "http://www.w3.org/2001/XMLSchema#double";
	ObjectMapper mapper;
	IModelStore modelStore;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		SpdxModelFactory.init();
		mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
		modelStore = new InMemSpdxStore();
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for serializing All Objects
	 * @throws GenerationException 
	 * @throws InvalidSPDXAnalysisException 
	 */
	@Test
	public void testSerializeAllObjects() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);

		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		CreationInfo creationInfo = pkg.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = pkg.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		
		JsonNode result = serializer.serialize(null);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultCreationInfos = new ArrayList<>();
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if ("CreationInfo".equals(type.asText())) {
				resultCreationInfos.add(element);
			} else {
				resultElements.add(element);
			}
		});
		assertEquals(1, resultCreationInfos.size());
		JsonNode resultCreationInfo = resultCreationInfos.get(0);
		assertEquals(createdDate, resultCreationInfo.get("created").asText());
		assertEquals(specVersion, resultCreationInfo.get("specVersion").asText());
		List<JsonNode> resultCreatedBys = new ArrayList<>();
		resultCreationInfo.get("createdBy").elements().forEachRemaining(element -> resultCreatedBys.add(element));
		assertEquals(1, resultCreatedBys.size());
		assertEquals(agentUri, resultCreatedBys.get(0).asText());
		String creationInfoId = resultCreationInfo.get("@id").asText();
		
		assertEquals(2, resultElements.size());
		JsonNode resultCreatedBy;
		JsonNode resultPkg;
		if (resultElements.get(0).get("type").asText().equals("Person")) {
			resultCreatedBy = resultElements.get(0);
			resultPkg = resultElements.get(1);
		} else {
			resultCreatedBy = resultElements.get(1);
			resultPkg = resultElements.get(0);
		}
		assertEquals(creationInfoId, resultCreatedBy.get("creationInfo").asText());
		assertEquals(agentUri, resultCreatedBy.get("spdxId").asText());
		assertEquals("Person", resultCreatedBy.get("type").asText());
		assertEquals(createdName, resultCreatedBy.get("name").asText());
		
		assertEquals(creationInfoId, resultPkg.get("creationInfo").asText());
		assertEquals(pkgUri, resultPkg.get("spdxId").asText());
		assertEquals(pkgName, resultPkg.get("name").asText());
		List<JsonNode> resultVerfiedUsings = new ArrayList<>();
		resultPkg.get("verifiedUsing").elements().forEachRemaining(node -> resultVerfiedUsings.add(node));
		assertEquals(1, resultVerfiedUsings.size());
		JsonNode resultHash = resultVerfiedUsings.get(0);
		assertTrue(resultHash.isObject());
		assertEquals("Hash", resultHash.get("type").asText());
		assertEquals(hashValue, resultHash.get("hashValue").asText());
		assertEquals(hashAlgorithm.getLongName(), resultHash.get("algorithm").asText());
		
		assertTrue(serializer.getSchema().validate(result));
	}
	
	/**
	 * Test method for get schema validation
	 * @throws GenerationException 
	 * @throws InvalidSPDXAnalysisException 
	 */
	@Test
	public void testSerializeValidate() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);

		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		Agent createdBy = new Person(modelStore, agentUri, copyManager, true, prefix);
		createdBy.setName(createdName);

		
		CreationInfo creationInfo = createdBy.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		createdBy.setCreationInfo(creationInfo);
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		
		JsonNode result = serializer.serialize(null);
		assertTrue(serializer.getSchema().validate(result));
	}
	
	@Test
	public void testSerializeSingleElement() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		CreationInfo creationInfo = pkg.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = pkg.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		
		JsonNode result = serializer.serialize(pkg);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultCreationInfos = new ArrayList<>();
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if ("CreationInfo".equals(type.asText())) {
				resultCreationInfos.add(element);
			} else {
				resultElements.add(element);
			}
		});
		
		assertEquals(1, resultElements.size());
		JsonNode resultCreationInfo = resultElements.get(0).get("creationInfo");
		assertTrue(resultCreationInfos.isEmpty());
		assertEquals(createdDate, resultCreationInfo.get("created").asText());
		assertEquals(specVersion, resultCreationInfo.get("specVersion").asText());
		List<JsonNode> resultCreatedBys = new ArrayList<>();
		resultCreationInfo.get("createdBy").elements().forEachRemaining(element -> resultCreatedBys.add(element));
		assertEquals(1, resultCreatedBys.size());
		assertEquals(agentUri, resultCreatedBys.get(0).asText());
		assertEquals(pkgUri, resultElements.get(0).get("spdxId").asText());
		assertEquals(pkgName, resultElements.get(0).get("name").asText());
		List<JsonNode> resultVerfiedUsings = new ArrayList<>();
		resultElements.get(0).get("verifiedUsing").elements().forEachRemaining(node -> resultVerfiedUsings.add(node));
		assertEquals(1, resultVerfiedUsings.size());
		JsonNode resultHash = resultVerfiedUsings.get(0);
		assertTrue(resultHash.isObject());
		assertEquals("Hash", resultHash.get("type").asText());
		assertEquals(hashValue, resultHash.get("hashValue").asText());
		assertEquals(hashAlgorithm.getLongName(), resultHash.get("algorithm").asText());
		
		assertTrue(serializer.getSchema().validate(result));
	}
	
	@Test
	public void testSerializeSpdxDocumentElement() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		String fileName1 = "File";
		String fileUri1 = "https://my/unique/file1";
		String fileName2 = "secondFile";
		String fileUri2 = "https://my/unique/file2";
		String fileName3 = "thirdFile";
		String fileUri3 = "https://my/unique/file3";
		String externalElementUri = "http://external";
		String relationshipUri = "urn:this:is:relationship";
		String documentUri = "urn:my:document";
		String externalLocationHint = "https://location/is/here";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		CreationInfo creationInfo = pkg.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = pkg.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		SpdxFile file1 = pkg.createSpdxFile(fileUri1)
				.setName(fileName1)
				.build();
		SpdxFile file2 = pkg.createSpdxFile(fileUri2)
				.setName(fileName2)
				.build();
		@SuppressWarnings("unused")
		SpdxFile file3 = pkg.createSpdxFile(fileUri3)
				.setName(fileName3)
				.build();
		ExternalElement externalElement = new ExternalElement(externalElementUri);
		Relationship relationship = pkg.createRelationship(relationshipUri)
				.setFrom(pkg)
				.addTo(externalElement)
				.setRelationshipType(RelationshipType.CONTAINS)
				.build();
		
		SpdxDocument spdxDoc = pkg.createSpdxDocument(documentUri)
				.addSpdxImport(pkg.createExternalMap(modelStore.getNextId(IdType.Anonymous))
						.setExternalSpdxId(externalElementUri)
						.setLocationHint(externalLocationHint)
						.build())
				.addRootElement(pkg)
				.addRootElement(file2)
				.addElement(pkg)
				.addElement(file1)
				.addElement(relationship)
				.build();
		JsonNode result = serializer.serialize(spdxDoc);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultCreationInfos = new ArrayList<>();
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if ("CreationInfo".equals(type.asText())) {
				resultCreationInfos.add(element);
			} else {
				resultElements.add(element);
			}
		});
		assertEquals(1, resultCreationInfos.size());
		JsonNode resultCreationInfo = resultCreationInfos.get(0);
		assertEquals(createdDate, resultCreationInfo.get("created").asText());
		assertEquals(specVersion, resultCreationInfo.get("specVersion").asText());
		List<JsonNode> resultCreatedBys = new ArrayList<>();
		resultCreationInfo.get("createdBy").elements().forEachRemaining(element -> resultCreatedBys.add(element));
		assertEquals(1, resultCreatedBys.size());
		assertEquals(agentUri, resultCreatedBys.get(0).asText());
		String creationInfoId = resultCreationInfo.get("@id").asText();
		
		assertEquals(5, resultElements.size());
		JsonNode docResult = null;
		JsonNode relationshipResult = null;
		JsonNode file1Result = null;
		JsonNode file2Result = null;
		JsonNode file3Result = null;
		JsonNode resultPkg = null;
		JsonNode resultExternal = null;
		for (JsonNode elementResult:resultElements) {
			if (documentUri.equals(elementResult.get("spdxId").asText())) {
				docResult = elementResult;
			}
			if (relationshipUri.equals(elementResult.get("spdxId").asText())) {
				relationshipResult = elementResult;
			}
			if (fileUri1.equals(elementResult.get("spdxId").asText())) {
				file1Result = elementResult;
			}
			if (fileUri2.equals(elementResult.get("spdxId").asText())) {
				file2Result = elementResult;
			}
			if (pkgUri.equals(elementResult.get("spdxId").asText())) {
				resultPkg = elementResult;
			} if (fileUri3.equals(elementResult.get("spdxId").asText())) {
				file3Result = elementResult;
			} if (externalElementUri.equals(elementResult.get("spdxId").asText())) {
				resultExternal = elementResult;
			}
		}
		assertEquals(creationInfoId, resultPkg.get("creationInfo").asText());
		assertEquals(pkgName, resultPkg.get("name").asText());
		assertTrue(Objects.nonNull(docResult));
		assertTrue(Objects.nonNull(file2Result));
		assertEquals(fileName2, file2Result.get("name").asText());
		assertTrue(Objects.nonNull(file1Result));
		assertEquals(fileName1, file1Result.get("name").asText());
		assertTrue(Objects.isNull(file3Result));
		assertTrue(Objects.nonNull(relationshipResult));
		assertEquals(pkgUri, relationshipResult.get("from").asText());
		assertTrue(relationshipResult.get("to").isArray());
		assertEquals(1, relationshipResult.withArrayProperty("to").size());
		assertEquals(externalElementUri, relationshipResult.withArrayProperty("to").get(0).asText());
		assertEquals(RelationshipType.CONTAINS.getLongName(), relationshipResult.get("relationshipType").asText());
		assertTrue(Objects.isNull(resultExternal));
	}

	@Test
	public void testSerializeDouble() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String relUri = prefix + "REL";
		String vulnUri = prefix + "VULN";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		double score = 4.3;

		ModelCopyManager copyManager = new ModelCopyManager();
		CvssV3VulnAssessmentRelationship rel = new CvssV3VulnAssessmentRelationship(modelStore, relUri, copyManager, true, prefix);
		CreationInfo creationInfo = rel.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = rel.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		rel.setCreationInfo(creationInfo);
		rel.setRelationshipType(RelationshipType.HAS_ASSESSMENT_FOR);
		Vulnerability vuln = rel.createVulnerability(vulnUri).build();
		rel.setFrom(vuln);
		SpdxPackage pkg = rel.createSpdxPackage(pkgUri).setName(pkgName).build();
		rel.getTos().add(pkg);
		rel.setScore(score);
		rel.setVectorString("(AV:N/AC:M/Au:N/C:P/I:N/A:N)");

		JsonNode result = serializer.serialize(rel);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if (!"CreationInfo".equals(type.asText())) {
				resultElements.add(element);
			}
		});

		assertEquals(1, resultElements.size());
		assertEquals(relUri, resultElements.get(0).get("spdxId").asText());
		JsonNode scoreResult = resultElements.get(0).get("security_score");
		assertEquals(score, scoreResult.asDouble(), 0.00001);
	}

	/**
	 * Non-integer numbers in extension properties must be serialized as JSON numbers
	 */
	@Test
	public void testSerializeExtensionPropertyDouble() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String personUri = prefix + "PERSON";
		String extNamespace = "https://example.org/spdx3-ext/test/";
		Person person = createPerson(personUri, prefix);
		modelStore.setValue(personUri, new PropertyDescriptor("fraction", extNamespace), 0.35);
		modelStore.setValue(personUri, new PropertyDescriptor("floatValue", extNamespace), 1.5f);
		modelStore.setValue(personUri, new PropertyDescriptor("integralDouble", extNamespace), 3.0);
		modelStore.setValue(personUri, new PropertyDescriptor("nan", extNamespace), Double.NaN);
		modelStore.setValue(personUri, new PropertyDescriptor("inf", extNamespace), Double.POSITIVE_INFINITY);
		modelStore.setValue(personUri, new PropertyDescriptor("negInf", extNamespace), Double.NEGATIVE_INFINITY);
		modelStore.setValue(personUri, new PropertyDescriptor("big", extNamespace),
				new TypedLiteral("9007199254740993", XSD_INTEGER));
		modelStore.addValueToCollection(personUri, new PropertyDescriptor("doubles", extNamespace), 0.1);
		modelStore.addValueToCollection(personUri, new PropertyDescriptor("doubles", extNamespace), 0.2);

		JsonNode personResult = serializePerson(serializer, person);
		JsonNode fraction = personResult.get(extNamespace + "fraction");
		assertTrue(fraction.isNumber());
		assertEquals(0.35, fraction.asDouble(), 0.0);
		JsonNode floatValue = personResult.get(extNamespace + "floatValue");
		assertTrue(floatValue.isNumber());
		assertEquals(1.5, floatValue.asDouble(), 0.0);
		// an integral double written as a JSON number would be read back as an integer
		assertEquals(valueObject("3.0", XSD_DOUBLE), personResult.get(extNamespace + "integralDouble"));
		assertEquals(valueObject("NaN", XSD_DOUBLE), personResult.get(extNamespace + "nan"));
		assertEquals(valueObject("INF", XSD_DOUBLE), personResult.get(extNamespace + "inf"));
		assertEquals(valueObject("-INF", XSD_DOUBLE), personResult.get(extNamespace + "negInf"));
		assertEquals(valueObject("9007199254740993", XSD_INTEGER), personResult.get(extNamespace + "big"));
		JsonNode doubles = personResult.get(extNamespace + "doubles");
		assertEquals(2, doubles.size());
		for (JsonNode d : doubles) {
			assertTrue(d.isNumber());
		}
	}

	private JsonNode valueObject(String value, String datatype) {
		ObjectNode retval = mapper.createObjectNode();
		retval.put("@value", value);
		retval.put("@type", datatype);
		return retval;
	}

	private Person createPerson(String personUri, String prefix) throws InvalidSPDXAnalysisException {
		ModelCopyManager copyManager = new ModelCopyManager();
		Person person = new Person(modelStore, personUri, copyManager, true, prefix);
		CreationInfo creationInfo = person.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated("2024-07-22T16:01:15Z")
				.setSpecVersion("3.0.1")
				.build();
		creationInfo.getCreatedBys().add(person);
		person.setCreationInfo(creationInfo);
		person.setName("Person Name");
		return person;
	}

	private JsonNode serializePerson(JsonLDSerializer serializer, Person person) throws InvalidSPDXAnalysisException {
		JsonNode result = serializer.serialize(person);
		for (JsonNode element : result.get("@graph")) {
			if ("Person".equals(element.get("type").asText())) {
				return element;
			}
		}
		fail("Person not found");
		return null;
	}

	/**
	 * SPDX decimal properties must be written in a form the SPDX JSON schema accepts
	 */
	@Test
	public void testSerializeSpdxDecimal() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String personUri = prefix + "PERSON";
		Person person = createPerson(personUri, prefix);
		// a decimal property, not checked by the store for the element type
		modelStore.setValue(personUri, SpdxConstantsV3.PROP_SCORE, 1e-7);
		JsonNode score = serializePerson(serializer, person).get("security_score");
		assertEquals("0.0000001", score.asText());
		assertTrue(score.asText().matches("^-?[0-9]+(\\.[0-9]*)?$"));
		modelStore.setValue(personUri, SpdxConstantsV3.PROP_SCORE, 1e22);
		assertEquals("10000000000000000000000", serializePerson(serializer, person).get("security_score").asText());
		modelStore.setValue(personUri, SpdxConstantsV3.PROP_SCORE, Double.NaN);
		try {
			serializer.serialize(person);
			fail("NaN is not a valid decimal");
		} catch (InvalidSPDXAnalysisException e) {
			// expected
		}
		modelStore.setValue(personUri, SpdxConstantsV3.PROP_SCORE, new TypedLiteral("1.5", XSD_DOUBLE));
		try {
			serializer.serialize(person);
			fail("A typed literal is not a valid value of an SPDX property");
		} catch (InvalidSPDXAnalysisException e) {
			// expected
		}
	}

	/**
	 * A property is an SPDX property only if its term is defined in the SPDX JSON-LD context
	 */
	@Test
	public void testIsSpdxProperty() throws Exception {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		for (java.lang.reflect.Field field : SpdxConstantsV3.class.getFields()) {
			// PROP_SECURITY_LOCATOR has the name "SecurityLocator" instead of "locator" in spdx-java-model-3_0
			if (field.getName().startsWith("PROP_") && field.getType().equals(PropertyDescriptor.class) &&
					!"PROP_SECURITY_LOCATOR".equals(field.getName())) {
				PropertyDescriptor prop = (PropertyDescriptor) field.get(null);
				assertTrue(prop.toString(), serializer.isSpdxProperty(prop));
			}
		}
		assertFalse(serializer.isSpdxProperty(new PropertyDescriptor("myProp", "https://spdx.org/rdf/3.0.1/terms/Extension/")));
		assertFalse(serializer.isSpdxProperty(new PropertyDescriptor("name", "https://spdx.org/rdf/3.0.0/terms/Core/")));
		assertFalse(serializer.isSpdxProperty(new PropertyDescriptor("name", "https://example.org/ext/")));

		String prefix = "http://test.uri#";
		String personUri = prefix + "PERSON";
		Person person = createPerson(personUri, prefix);
		modelStore.setValue(personUri, new PropertyDescriptor("myProp", "https://spdx.org/rdf/3.0.1/terms/Extension/"), "x");
		modelStore.setValue(personUri, new PropertyDescriptor("comment", "https://spdx.org/rdf/3.0.0/terms/Core/"), "y");
		JsonNode personResult = serializePerson(serializer, person);
		assertEquals("x", personResult.get("https://spdx.org/rdf/3.0.1/terms/Extension/myProp").asText());
		assertEquals("y", personResult.get("https://spdx.org/rdf/3.0.0/terms/Core/comment").asText());
		assertNull(personResult.get("extension_myProp"));
		assertNull(personResult.get("comment"));
	}
}
