/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.core.IndividualUriValue;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.ModelRegistry;
import org.spdx.core.TypedLiteral;
import org.spdx.core.TypedValue;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.SpdxConstantsV3;
import org.spdx.library.model.v3_0_1.core.Agent;
import org.spdx.library.model.v3_0_1.core.CreationInfo;
import org.spdx.library.model.v3_0_1.core.Element;
import org.spdx.library.model.v3_0_1.core.HashAlgorithm;
import org.spdx.library.model.v3_0_1.core.ProfileIdentifierType;
import org.spdx.library.model.v3_0_1.core.Relationship;
import org.spdx.library.model.v3_0_1.core.RelationshipType;
import org.spdx.library.model.v3_0_1.core.SpdxDocument;
import org.spdx.library.model.v3_0_1.extension.Extension;
import org.spdx.library.model.v3_0_1.software.Sbom;
import org.spdx.library.model.v3_0_1.software.SbomType;
import org.spdx.library.model.v3_0_1.software.SpdxFile;
import org.spdx.library.model.v3_0_1.software.SpdxPackage;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.PropertyDescriptor;
import org.spdx.storage.simple.InMemSpdxStore;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * @author Gary O'Neall
 */
public class JsonLDStoreTest {
	private static final String PACKAGE_SBOM_FILE = "package_sbom.json";
	private static final String NO_DOCUMENT_FILE = "no_document.json";
	private static final String YOCTO_SPDX_FILE = "core-image-minimal.json";
	private static final String CUSTOM_EXTENSION_FILE = "custom_extension.json";
	private static final String EXTENSION_MINIMAL_FILE = "extension_minimal.json";
	private static final String SHARED_IRI_EXTERNAL_REF_FILE = "shared_iri_external_ref.json";
	private static final String DATASET_ID = "https://example.org/spdx/dataset/instruct-mix";
	private static final String X = "https://example.org/x/";
	private static final String EXT_NS = "https://example.org/spdx3-ext/synthetic-data/";
	private static final String SYNTHETIC_DATA_EXTENSION_TYPE = EXT_NS + "SyntheticDataExtension";
	private static final String XSD_DECIMAL = "http://www.w3.org/2001/XMLSchema#decimal";
	private static final String XSD_DATE_TIME = "http://www.w3.org/2001/XMLSchema#dateTime";
	IModelStore innerStore;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		innerStore = new InMemSpdxStore();
		SpdxModelFactory.init();
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * @throws Exception 
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDStore#JsonLDStore(org.spdx.storage.IModelStore, boolean)}.
	 * @throws  
	 */
	@Test
	public void testJsonLDStoreIModelStoreBoolean() throws Exception {
		try (JsonLDStore ldStore = new JsonLDStore(innerStore, false)) {
			assertFalse(ldStore.getPretty());
		}
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDStore#serialize(java.io.OutputStream)}.
	 * @throws InvalidSPDXAnalysisException 
	 */
	@Test
	public void testSerialize() throws Exception {
		
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			String prefix = "http://test.uri#";
			String pkgUri = prefix + "PACKAGE";
			String agentUri = prefix + "AGENT";
			String createdName = "Creator";
			String createdDate = "2024-07-22T16:01:15Z";
			String specVersion = "3.0.1";
			String pkgName = "Package Name";
			HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
			String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
			
			ModelCopyManager copyManager = new ModelCopyManager();
			SpdxPackage pkg = new SpdxPackage(ldStore, pkgUri, copyManager, true, prefix);
			CreationInfo creationInfo = new CreationInfo(ldStore, ldStore.getNextId(IdType.Anonymous),
					copyManager, true, prefix);
			creationInfo.setCreated(createdDate)
					.setSpecVersion(specVersion);
			Agent createdBy = creationInfo.createPerson(agentUri)
					.setCreationInfo(creationInfo)
					.setName(createdName)
					.build();
			creationInfo.getCreatedBys().add(createdBy);
			pkg.setCreationInfo(creationInfo);
			pkg.setName(pkgName);
			pkg.getVerifiedUsings().add(pkg.createHash(ldStore.getNextId(IdType.Anonymous))
					.setAlgorithm(hashAlgorithm)
					.setHashValue(hashValue)
					.build());
			
			String result;
			try (ByteArrayOutputStream bas = new ByteArrayOutputStream()) {
				ldStore.serialize(bas);
				result = bas.toString();
			}
			
			ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
			JsonNode root = mapper.readTree(result);
			JsonLDSchema jsonLDSchema = new JsonLDSchema(String.format("schema-v%s.json",  specVersion),
					String.format("spdx-context-v%s.jsonld",  specVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			assertTrue(jsonLDSchema.validate(root));
		}
	}
	
	@Test
	public void testValidateTestFile() throws Exception {
		String specVersion = "3.0.1";
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(PACKAGE_SBOM_FILE)) {
			ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
			JsonNode root = mapper.readTree(is);
			JsonLDSchema jsonLDSchema = new JsonLDSchema(String.format("schema-v%s.json",  specVersion),
					String.format("spdx-context-v%s.jsonld",  specVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			assertTrue(jsonLDSchema.validate(root));
		}
		
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDStore#deSerialize(java.io.InputStream, boolean)}.
	 * @throws Exception 
	 */
	@Test
	public void testDeSerialize() throws Exception {
		
		String specVersion = "3.0.1";
		String created = "2024-03-06T00:00:00Z";
		String personSpdxId = "http://spdx.example.com/Agent/JoshuaWatt";
		String documentSpdxId = "http://spdx.example.com/Document1";
		String sbomSpdxId = "http://spdx.example.com/BOM1";
		String packageSpdxId = "http://spdx.example.com/Package1";
		String fileSpdxId = "http://spdx.example.com/Package1/myprogram";
		String relationshipSpdxId = "http://spdx.example.com/Relationship/1";
		String personName = "Joshua Watt";
		List<ProfileIdentifierType> conformances = Arrays.asList(new ProfileIdentifierType[] {
				ProfileIdentifierType.CORE, ProfileIdentifierType.SOFTWARE
		});
		List<String> conformancesStr = new ArrayList<>();
		conformances.forEach(con -> conformancesStr.add(con.getLongName()));
		List<SbomType> sbomTypes = Arrays.asList(new SbomType[] {SbomType.BUILD});
		List<String> sbomTypesStr = new ArrayList<>();
		sbomTypes.forEach(sbomType -> sbomTypesStr.add(sbomType.getLongName()));
		String packageName = "my-package";
		String packageVersion = "1.0";
		String packageDownloadLocation = "http://dl.example.com/my-package_1.0.0.tar";
		String packageBuiltTime = "2024-03-06T00:00:00Z";
		List<String> originated = Arrays.asList(new String[] {personSpdxId});
		String fileName = "myprogram";
		String primaryPurpose = "executable";
		String fileCopyright = "Copyright 2024, Joshua Watt";
		String completeness = "complete";
		RelationshipType relationshipType = RelationshipType.CONTAINS;
		
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			try (InputStream is = getClass().getClassLoader().getResourceAsStream(PACKAGE_SBOM_FILE)) {
				ldStore.deSerialize(is, false);
			}
			
			SpdxDocument documentResult = (SpdxDocument)SpdxModelFactory.inflateModelObject(ldStore, documentSpdxId, SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, specVersion, false, "");
			assertEquals(1, documentResult.getRootElements().size());
			assertEquals(sbomSpdxId, documentResult.getRootElements().toArray(new Element[1])[0].getObjectUri());
			assertEquals(conformancesStr.size(), documentResult.getProfileConformances().size());
			assertTrue(documentResult.getProfileConformances().containsAll(conformances));
			assertEquals(created, documentResult.getCreationInfo().getCreated());
			assertEquals(personName, documentResult.getCreationInfo().getCreatedBys().toArray(new Agent[documentResult.getCreationInfo().getCreatedBys().size()])[0].getName().get());
			
			Sbom sbomResult = (Sbom)SpdxModelFactory.inflateModelObject(ldStore, sbomSpdxId, SpdxConstantsV3.SOFTWARE_SBOM, null, specVersion, false, "");
			assertEquals(1, sbomResult.getRootElements().size());
			assertEquals(packageSpdxId, sbomResult.getRootElements().toArray(new Element[1])[0].getObjectUri());
			assertEquals(sbomTypes.size(), sbomResult.getSbomTypes().size());
			assertTrue(sbomResult.getSbomTypes().containsAll(sbomTypes));
			
			SpdxPackage packageResult = (SpdxPackage)SpdxModelFactory.inflateModelObject(ldStore, packageSpdxId, SpdxConstantsV3.SOFTWARE_SPDX_PACKAGE, null, specVersion, false, "");
			assertEquals(packageName, packageResult.getName().get());
			assertEquals(packageVersion, packageResult.getPackageVersion().get());
			assertEquals(packageDownloadLocation, packageResult.getDownloadLocation().get());
			assertEquals(packageBuiltTime, packageResult.getBuiltTime().get());
			assertEquals(originated.size(), packageResult.getOriginatedBys().size());
			packageResult.getOriginatedBys().forEach(agent -> assertTrue(originated.contains(agent.getObjectUri())));
			
			SpdxFile fileResult = (SpdxFile)SpdxModelFactory.inflateModelObject(ldStore, fileSpdxId, SpdxConstantsV3.SOFTWARE_SPDX_FILE, null, specVersion, false, "");
			assertEquals(fileName, fileResult.getName().get());
			assertEquals(primaryPurpose, fileResult.getPrimaryPurpose().get().getLongName());
			assertEquals(fileCopyright, fileResult.getCopyrightText().get());
			
			Relationship relationshipResult = (Relationship)SpdxModelFactory.inflateModelObject(ldStore, relationshipSpdxId, SpdxConstantsV3.CORE_RELATIONSHIP, null, specVersion, false, "");
			assertEquals(packageSpdxId, relationshipResult.getFrom().getObjectUri());
			assertEquals(1, relationshipResult.getTos().size());
			assertEquals(fileSpdxId, relationshipResult.getTos().toArray(new Element[1])[0].getObjectUri());
			assertEquals(relationshipType, relationshipResult.getRelationshipType());
			assertEquals(completeness, relationshipResult.getCompleteness().get().getLongName());
			
			List<String> verifyResult = documentResult.verify();
			assertTrue(verifyResult.isEmpty());
			
			try (InputStream is = getClass().getClassLoader().getResourceAsStream(PACKAGE_SBOM_FILE)) {
				try {
					ldStore.deSerialize(is, false);
					fail("No overwrite should faild here");
				} catch (InvalidSPDXAnalysisException ex) {
					//expected
				}
			}
		}
	}

	/**
	 * Test deserializing a file wihtout an SPDX document
	 * @throws Exception on error
	 */
	@Test
	public void testDeserializeNoSpdxDocument() throws Exception {

		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			try (InputStream is = getClass().getClassLoader().getResourceAsStream(NO_DOCUMENT_FILE)) {
				ldStore.deSerialize(is, false);
			}
			List<SpdxDocument> docs =
					SpdxModelFactory.getSpdxObjects(ldStore, null, SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, null)
							.map(SpdxDocument.class::cast)
							.collect(Collectors.toList());
			assertEquals(1, docs.size());
			SpdxDocument doc = docs.get(0);
			assertEquals(2, doc.getElements().size());
			List<String> verify = doc.verify();
			assertTrue(verify.isEmpty());
		}
	}

	/**
	 * Test deserializing a Yocto-generated SPDX 3 file
	 * @throws Exception on error
	 */
	@Test
	public void testDeserializeYoctoSpdxDocument() throws Exception {
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			try (InputStream is = getClass().getClassLoader().getResourceAsStream(YOCTO_SPDX_FILE)) {
				ldStore.deSerialize(is, false);
			}
			List<SpdxDocument> docs =
					SpdxModelFactory.getSpdxObjects(ldStore, null, SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, null)
							.map(SpdxDocument.class::cast)
							.collect(Collectors.toList());
			assertEquals(1, docs.size());
			SpdxDocument doc = docs.get(0);
			assertEquals(17805, doc.getElements().size());
			List<String> verify = doc.verify();
			assertTrue(verify.isEmpty());
		}
	}

	/**
	 * Find the graph node with the given spdxId
	 */
	private static JsonNode findGraphNode(JsonNode root, String spdxId) {
		for (JsonNode node : root.get("@graph")) {
			if (node.has("spdxId") && spdxId.equals(node.get("spdxId").asText())) {
				return node;
			}
		}
		return null;
	}

	/**
	 * Find the extension object with the given type in an element node
	 */
	private static JsonNode findExtensionNode(JsonNode elementNode, String type) {
		for (JsonNode ext : elementNode.get("extension")) {
			if (type.equals(ext.get("type").asText())) {
				return ext;
			}
		}
		return null;
	}

	/**
	 * Custom extension types (full IRIs) and JSON-LD value objects in extension properties
	 * must deserialize, verify, and serialize back without loss
	 * @throws Exception on error
	 */
	@Test
	public void testCustomExtensionRoundTrip() throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		JsonNode input;
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(CUSTOM_EXTENSION_FILE)) {
			input = mapper.readTree(is);
		}
		String datasetId = "https://example.org/spdx/dataset/instruct-mix";
		String teacherId = "https://example.org/spdx/model/teacher-llm";
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			try (InputStream is = getClass().getClassLoader().getResourceAsStream(CUSTOM_EXTENSION_FILE)) {
				ldStore.deSerialize(is, false);
			}
			List<SpdxDocument> docs =
					SpdxModelFactory.getSpdxObjects(ldStore, null, SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, null)
							.map(SpdxDocument.class::cast)
							.collect(Collectors.toList());
			assertEquals(1, docs.size());
			List<String> verify = docs.get(0).verify();
			assertTrue(verify.toString(), verify.isEmpty());

			// model view of the extensions
			Element dataset = (Element) SpdxModelFactory.inflateModelObject(ldStore, datasetId,
					SpdxConstantsV3.DATASET_DATASET_PACKAGE, null, "3.0.1", false, "");
			assertEquals(2, dataset.getExtensions().size());
			Extension synthetic = null;
			for (Extension ext : dataset.getExtensions()) {
				if (SYNTHETIC_DATA_EXTENSION_TYPE.equals(ext.getType())) {
					synthetic = ext;
				}
			}
			assertNotNull(synthetic);
			assertTrue(synthetic instanceof GenericExtension);
			Object fraction = ldStore.getValue(synthetic.getObjectUri(),
					new PropertyDescriptor("syntheticFraction", EXT_NS)).get();
			assertEquals(new TypedLiteral("0.35", XSD_DECIMAL), fraction);
			Object method = ldStore.getValue(synthetic.getObjectUri(),
					new PropertyDescriptor("generationMethod", EXT_NS)).get();
			assertTrue(method instanceof IndividualUriValue);
			assertEquals(EXT_NS + "DataGenerationMethodType/mixed", ((IndividualUriValue) method).getIndividualURI());
			Object generator = ldStore.getValue(synthetic.getObjectUri(),
					new PropertyDescriptor("generatorModel", EXT_NS)).get();
			assertTrue(generator instanceof TypedValue);
			assertEquals(teacherId, ((TypedValue) generator).getObjectUri());

			// serialize and compare the extension objects
			JsonNode output;
			try (ByteArrayOutputStream bas = new ByteArrayOutputStream()) {
				ldStore.serialize(bas);
				output = mapper.readTree(bas.toString());
			}
			for (String elementId : new String[] {datasetId, teacherId}) {
				JsonNode inElement = findGraphNode(input, elementId);
				JsonNode outElement = findGraphNode(output, elementId);
				assertNotNull(outElement);
				assertEquals(inElement.get("extension").size(), outElement.get("extension").size());
				for (JsonNode inExt : inElement.get("extension")) {
					JsonNode outExt = findExtensionNode(outElement, inExt.get("type").asText());
					assertEquals(inExt, outExt);
				}
			}
		}
	}

	/**
	 * Reads a test resource as JSON
	 */
	private JsonNode readResource(String resource) throws Exception {
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(resource)) {
			return new ObjectMapper().readTree(is);
		}
	}

	/**
	 * @return the minimal extension document with the extension of the dataset replaced by the extension object
	 */
	private ObjectNode documentWithExtension(String extensionJson) throws Exception {
		ObjectNode doc = (ObjectNode) readResource(EXTENSION_MINIMAL_FILE);
		ObjectNode dataset = (ObjectNode) findGraphNode(doc, DATASET_ID);
		dataset.putArray("extension").add(new ObjectMapper().readTree(extensionJson));
		return doc;
	}

	/**
	 * Deserializes the document into a new store, then serializes it
	 */
	private JsonNode roundTrip(JsonNode doc) throws Exception {
		try (JsonLDStore ldStore = new JsonLDStore(new InMemSpdxStore())) {
			SpdxDocument spdxDoc = ldStore.deSerialize(new ByteArrayInputStream(doc.toString().getBytes(StandardCharsets.UTF_8)), false);
			List<String> verify = spdxDoc.verify();
			assertTrue(verify.toString(), verify.isEmpty());
			try (ByteArrayOutputStream bas = new ByteArrayOutputStream()) {
				ldStore.serialize(bas);
				return new ObjectMapper().readTree(bas.toString());
			}
		}
	}

	/**
	 * @return the JSON with arrays sorted, since JSON-LD arrays are unordered
	 */
	private static JsonNode canonical(JsonNode node) {
		if (node.isArray()) {
			List<JsonNode> items = new ArrayList<>();
			node.forEach(item -> items.add(canonical(item)));
			items.sort((a, b) -> a.toString().compareTo(b.toString()));
			ArrayNode retval = new ObjectMapper().createArrayNode();
			retval.addAll(items);
			return retval;
		} else if (node.isObject()) {
			ObjectNode retval = new ObjectMapper().createObjectNode();
			node.properties().forEach(field -> retval.set(field.getKey(), canonical(field.getValue())));
			return retval;
		} else {
			return node;
		}
	}

	/**
	 * Deserializing and serializing the result again must not change it
	 */
	private JsonNode assertStableRoundTrip(JsonNode doc) throws Exception {
		JsonNode first = roundTrip(doc);
		JsonNode second = roundTrip(first);
		assertEquals(canonical(first), canonical(second));
		return first;
	}

	/**
	 * @return the number of values of the property in all objects in the JSON
	 */
	private static int countValues(JsonNode node, String property) {
		int count = 0;
		if (node.isArray()) {
			for (JsonNode item : node) {
				count += countValues(item, property);
			}
		} else if (node.isObject()) {
			for (java.util.Map.Entry<String, JsonNode> field : node.properties()) {
				if (field.getKey().equals(property)) {
					count += field.getValue().isArray() ? field.getValue().size() : 1;
				} else {
					count += countValues(field.getValue(), property);
				}
			}
		}
		return count;
	}

	/**
	 * An object with an IRI used in several places must keep its values once
	 */
	@Test
	public void testSharedIriObjectRoundTrip() throws Exception {
		JsonNode input = readResource(SHARED_IRI_EXTERNAL_REF_FILE);
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			ldStore.deSerialize(new ByteArrayInputStream(input.toString().getBytes(StandardCharsets.UTF_8)), false);
			List<Object> locators = new ArrayList<>();
			ldStore.listValues("https://example.org/er1", SpdxConstantsV3.PROP_LOCATOR).forEachRemaining(locators::add);
			assertEquals(2, locators.size());
		}
		JsonNode output = assertStableRoundTrip(input);
		// inlined once, referenced elsewhere
		assertEquals(2, countValues(output, "locator"));
		assertEquals("https://example.org/er1", findGraphNode(output, "https://example.org/spdx/agent/alice").get("externalRef").get(0).isTextual() ?
				findGraphNode(output, "https://example.org/spdx/agent/alice").get("externalRef").get(0).asText() :
				findGraphNode(output, DATASET_ID).get("externalRef").get(0).asText());

		// custom nodes
		JsonNode customOutput = assertStableRoundTrip(documentWithExtension("{\"type\": \"" + X + "T\", "
				+ "\"" + X + "a\": {\"type\": \"" + X + "N\", \"@id\": \"https://example.org/n1\", \"" + X + "v\": [1, 2]}, "
				+ "\"" + X + "b\": {\"type\": \"" + X + "N\", \"@id\": \"https://example.org/n1\", \"" + X + "v\": [1, 2]}}"));
		assertEquals(2, countValues(customOutput, X + "v"));
		JsonNode ext = findGraphNode(customOutput, DATASET_ID).get("extension").get(0);
		JsonNode inlined = ext.get(X + "a").has(X + "v") ? ext.get(X + "a") : ext.get(X + "b");
		JsonNode reference = ext.get(X + "a").has(X + "v") ? ext.get(X + "b") : ext.get(X + "a");
		assertEquals("https://example.org/n1", inlined.get("@id").asText());
		assertEquals(new ObjectMapper().readTree("{\"@id\": \"https://example.org/n1\"}"), reference);
	}

	/**
	 * The occurrences of an object with an IRI are merged like a JSON-LD node map: the values
	 * of all occurrences are kept
	 */
	@Test
	public void testSharedIriObjectDifferentValues() throws Exception {
		ObjectNode input = (ObjectNode) readResource(SHARED_IRI_EXTERNAL_REF_FILE);
		ObjectNode first = (ObjectNode) findGraphNode(input, "https://example.org/spdx/agent/alice").get("externalRef").get(0);
		ObjectNode second = (ObjectNode) findGraphNode(input, DATASET_ID).get("externalRef").get(0);
		first.putArray("locator").add("a");
		second.putArray("locator").add("b").add("c");
		// the same value of a single-valued property is not a conflict
		first.put("comment", "same");
		second.put("comment", "same");
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			ldStore.deSerialize(new ByteArrayInputStream(input.toString().getBytes(StandardCharsets.UTF_8)), false);
			Set<Object> locators = new HashSet<>();
			ldStore.listValues("https://example.org/er1", SpdxConstantsV3.PROP_LOCATOR).forEachRemaining(locators::add);
			assertEquals(new HashSet<>(Arrays.asList("a", "b", "c")), locators);
			assertEquals("same", ldStore.getValue("https://example.org/er1", SpdxConstantsV3.PROP_COMMENT).get());
		}
		assertEquals(3, countValues(assertStableRoundTrip(input), "locator"));

		// a different value of a single-valued SPDX property is an error
		second.put("comment", "different");
		try {
			roundTrip(input);
			fail("Different values of a single-valued property");
		} catch (InvalidSPDXAnalysisException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("https://example.org/er1") && e.getMessage().contains("comment"));
		}

		// extension properties have no cardinality - the values are merged
		JsonNode customOutput = assertStableRoundTrip(documentWithExtension("{\"type\": \"" + X + "T\", "
				+ "\"" + X + "a\": {\"type\": \"" + X + "N\", \"@id\": \"https://example.org/n1\", \"" + X + "v\": 1, \"" + X + "w\": [1]}, "
				+ "\"" + X + "b\": {\"type\": \"" + X + "N\", \"@id\": \"https://example.org/n1\", \"" + X + "v\": 2, \"" + X + "w\": [1, 2]}}"));
		assertEquals(2, countValues(customOutput, X + "v"));
		assertEquals(2, countValues(customOutput, X + "w"));
	}

	/**
	 * Blank node references inside extension values
	 */
	@Test
	public void testBlankNodeReferenceInExtension() throws Exception {
		JsonNode doc = documentWithExtension("{\"type\": \"" + X + "T\", "
				+ "\"" + X + "a\": {\"type\": \"" + X + "N\", \"@id\": \"_:n1\", \"" + X + "v\": 1}, "
				+ "\"" + X + "b\": {\"@id\": \"_:n1\"}}");
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			ldStore.deSerialize(new ByteArrayInputStream(doc.toString().getBytes(StandardCharsets.UTF_8)), false);
			Element dataset = (Element) SpdxModelFactory.inflateModelObject(ldStore, DATASET_ID,
					SpdxConstantsV3.DATASET_DATASET_PACKAGE, null, "3.0.1", false, "");
			String extUri = dataset.getExtensions().iterator().next().getObjectUri();
			Object a = ldStore.getValue(extUri, new PropertyDescriptor("a", X)).get();
			Object b = ldStore.getValue(extUri, new PropertyDescriptor("b", X)).get();
			assertTrue(a instanceof TypedValue);
			assertEquals(a, b);
		}
		// a blank node referenced twice is written once with a blank node identifier
		JsonNode output = assertStableRoundTrip(doc);
		assertEquals(1, countValues(output, X + "v"));
		JsonNode ext = findGraphNode(output, DATASET_ID).get("extension").get(0);
		JsonNode inlined = ext.get(X + "a").has(X + "v") ? ext.get(X + "a") : ext.get(X + "b");
		JsonNode reference = ext.get(X + "a").has(X + "v") ? ext.get(X + "b") : ext.get(X + "a");
		assertTrue(inlined.get("@id").asText().startsWith("_:"));
		assertEquals(1, reference.size());
		assertEquals(inlined.get("@id"), reference.get("@id"));

		// a blank node reference to an unknown node is an error
		try {
			roundTrip(documentWithExtension("{\"type\": \"" + X + "T\", \"" + X + "a\": {\"@id\": \"_:nope\"}}"));
			fail("Unknown blank node reference");
		} catch (InvalidSPDXAnalysisException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("_:nope"));
		}
	}

	/**
	 * Custom types are only accepted for absolute IRIs outside of the SPDX namespace, where SPDX allows an extension
	 */
	@Test
	public void testCustomTypeRejected() throws Exception {
		String[] rejectedTypes = new String[] {
				"https://spdx.org/rdf/3.0.1/terms/Extension/Foo",	// unknown type in the SPDX namespace
				"spdx:Extension/Foo",	// compact IRI expanding to the SPDX namespace
				"FooExtension",	// not an absolute IRI
				"_:T",	// blank node identifier
		};
		for (String type : rejectedTypes) {
			try {
				roundTrip(documentWithExtension("{\"type\": \"" + type + "\", \"" + X + "a\": 1}"));
				fail("Type should be rejected: " + type);
			} catch (InvalidSPDXAnalysisException e) {
				assertTrue(e.getMessage(), e.getMessage().contains("Missing type"));
			}
		}
		// a custom type under a property which is not an extension
		ObjectNode doc = (ObjectNode) readResource(EXTENSION_MINIMAL_FILE);
		((ObjectNode) findGraphNode(doc, DATASET_ID)).putArray("verifiedUsing").add(
				new ObjectMapper().readTree("{\"type\": \"" + X + "H\", \"" + X + "a\": 1}"));
		try {
			roundTrip(doc);
			fail("Custom type under verifiedUsing should be rejected");
		} catch (InvalidSPDXAnalysisException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("Missing type"));
		}
		// a custom type at the top level of the graph
		doc = (ObjectNode) readResource(EXTENSION_MINIMAL_FILE);
		((ArrayNode) doc.get("@graph")).add(new ObjectMapper().readTree(
				"{\"type\": \"" + X + "T\", \"@id\": \"https://example.org/top\", \"" + X + "a\": 1}"));
		try {
			roundTrip(doc);
			fail("Custom type at the top level should be rejected");
		} catch (InvalidSPDXAnalysisException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("Missing type"));
		}
		// accepted custom types do not each need a registration
		roundTrip(documentWithExtension("{\"type\": \"urn:example:T\", \"" + X + "a\": 1}"));
		assertEquals(GenericExtension.class, ModelRegistry.getModelRegistry().getDefaultExtensionType());
	}

	/**
	 * JSON-LD value objects in extension properties
	 */
	@Test
	public void testExtensionValueObjects() throws Exception {
		String xsd = "http://www.w3.org/2001/XMLSchema#";
		JsonNode doc = documentWithExtension("{\"type\": \"" + X + "T\", "
				+ "\"" + X + "noType\": {\"@value\": 1.5}, "
				+ "\"" + X + "numInteger\": {\"@value\": 1e3, \"@type\": \"" + xsd + "integer\"}, "
				+ "\"" + X + "numDecimal\": {\"@value\": 0.5, \"@type\": \"" + xsd + "decimal\"}, "
				+ "\"" + X + "numDouble\": {\"@value\": 2, \"@type\": \"" + xsd + "double\"}, "
				+ "\"" + X + "bool\": {\"@value\": true, \"@type\": \"" + xsd + "boolean\"}, "
				+ "\"" + X + "compactType\": {\"@value\": \"0.35\", \"@type\": \"xsd:decimal\"}}");
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			ldStore.deSerialize(new ByteArrayInputStream(doc.toString().getBytes(StandardCharsets.UTF_8)), false);
			Element dataset = (Element) SpdxModelFactory.inflateModelObject(ldStore, DATASET_ID,
					SpdxConstantsV3.DATASET_DATASET_PACKAGE, null, "3.0.1", false, "");
			String extUri = dataset.getExtensions().iterator().next().getObjectUri();
			// @value without @type is the plain value
			assertEquals(1.5d, ldStore.getValue(extUri, new PropertyDescriptor("noType", X)).get());
			// numbers with a @type use the canonical lexical form of the JSON-LD 1.1 API section 8.2
			assertEquals(new TypedLiteral("1000", xsd + "integer"), ldStore.getValue(extUri, new PropertyDescriptor("numInteger", X)).get());
			assertEquals(new TypedLiteral("5.0E-1", xsd + "decimal"), ldStore.getValue(extUri, new PropertyDescriptor("numDecimal", X)).get());
			assertEquals(new TypedLiteral("2.0E0", xsd + "double"), ldStore.getValue(extUri, new PropertyDescriptor("numDouble", X)).get());
			assertEquals(new TypedLiteral("true", xsd + "boolean"), ldStore.getValue(extUri, new PropertyDescriptor("bool", X)).get());
			// a compact datatype is kept as written (with a warning) - the SPDX context defines no xsd prefix
			assertEquals(new TypedLiteral("0.35", "xsd:decimal"), ldStore.getValue(extUri, new PropertyDescriptor("compactType", X)).get());
		}
		assertStableRoundTrip(doc);

		String[][] rejected = new String[][] {
			{"{\"@value\": \"hi\", \"@language\": \"en\"}", "@language"},
			{"{\"@value\": \"hi\", \"@type\": \"@id\"}", "@id"},
			{"{\"@value\": \"hi\", \"@type\": \"relative/type\"}", "relative/type"},
			{"{\"@value\": \"hi\", \"@index\": \"i\"}", "@index"},
		};
		for (String[] r : rejected) {
			try {
				roundTrip(documentWithExtension("{\"type\": \"" + X + "T\", \"" + X + "a\": " + r[0] + "}"));
				fail("Value object should be rejected: " + r[0]);
			} catch (InvalidSPDXAnalysisException e) {
				assertTrue(e.getMessage(), e.getMessage().contains(r[1]));
			}
		}
	}
}
