/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.ModelRegistry;
import org.spdx.core.SimpleUriValue;
import org.spdx.core.TypedLiteral;
import org.spdx.core.TypedValue;
import org.spdx.library.ListedLicenses;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.SpdxConstantsV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.PropertyDescriptor;
import org.spdx.storage.listedlicense.SpdxListedLicenseModelStore;

import com.fasterxml.jackson.databind.JsonNode;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * Class to manage deserializing SPDX 3.X JSON-LD
 * 
 * @author Gary O'Neall
 */
public class JsonLDDeserializer {
	
	static final Logger logger = LoggerFactory.getLogger(JsonLDDeserializer.class);
	
	static final Set<String> ALL_SPDX_TYPES;
	static final Set<String> NON_PROPERTY_FIELD_NAMES;
	static final Map<String, String> JSON_PREFIX_TO_MODEL_PREFIX;

	static final String SPDX_ID_PROP = "spdxId";

	private static final String SPEC_VERSION_PROP = "specVersion";

	static final String XSD_INTEGER = "http://www.w3.org/2001/XMLSchema#integer";
	static final String XSD_DOUBLE = "http://www.w3.org/2001/XMLSchema#double";

	/**
	 * Prefixes commonly used in compact IRIs which the SPDX JSON-LD context does not define
	 */
	private static final Set<String> COMPACT_IRI_PREFIXES = Set.of("xsd", "rdf", "rdfs", "owl", "xml", "schema");

	/**
	 * JSON-LD 1.1 API section 8.2: a number with an absolute value of at least 10^21 is an xsd:double
	 */
	private static final BigDecimal MIN_DOUBLE_MAGNITUDE = new BigDecimal("1e21");
	/**
	 * JSON name of the Core extension property
	 */
	private static final String EXTENSION_PROP = "extension";

	/**
	 * Namespace prefix of all SPDX terms - types in this namespace are never custom types
	 */
	private static final String SPDX_NAMESPACE_PREFIX = "https://spdx.org/rdf/";
	
	static {
		Set<String> allSpdxTypes = new HashSet<>();
		Map<String, String> jsonPrefixToModelPrefix = new HashMap<>();
		Arrays.spliterator(SpdxConstantsV3.ALL_SPDX_CLASSES).forEachRemaining(c -> {
			allSpdxTypes.add(c);
			String nmSpace = c.split("\\.")[0];
			jsonPrefixToModelPrefix.put(nmSpace.toLowerCase(), nmSpace);
		});
		ALL_SPDX_TYPES = Collections.unmodifiableSet(allSpdxTypes);
		JSON_PREFIX_TO_MODEL_PREFIX = Collections.unmodifiableMap(jsonPrefixToModelPrefix);
		
		Set<String> nonPropertyFieldNames = new HashSet<>();
		nonPropertyFieldNames.add("@id");
		nonPropertyFieldNames.add(SPDX_ID_PROP);
		nonPropertyFieldNames.add("type");
		NON_PROPERTY_FIELD_NAMES = Collections.unmodifiableSet(nonPropertyFieldNames);
	}
	
	private final IModelStore modelStore;
	private final ModelCopyManager copyManager;
	private final ConcurrentMap<String, String> jsonAnonToStoreAnon = new ConcurrentHashMap<>();
	private final ConcurrentMap<String, JsonLDSchema> versionToSchema = new ConcurrentHashMap<>();
	/**
	 * Store URIs of the objects whose properties were deserialized in the current deserialization
	 */
	private final Set<String> deserializedObjectUris = ConcurrentHashMap.newKeySet();

	/**
	 * @param modelStore Model store to deserialize the JSON text into
	 */
	public JsonLDDeserializer(IModelStore modelStore) {
		this.modelStore = modelStore;
		this.copyManager = new ModelCopyManager();
	}

	/**
	 * Deserializes the JSON-LD graph into the modelStore
	 * @param graph Graph to deserialize
	 * @return list of non-anonymous typed value Elements found in the graph nodes
	 * @throws InvalidSPDXAnalysisException on SPDX parsing errors
	 */
	public List<TypedValue> deserializeGraph(JsonNode graph) throws InvalidSPDXAnalysisException {
		List<TypedValue> nonAnonGraphItems = new ArrayList<>();
		if (!graph.isArray()) {
			logger.error("Invalid type for deserializeGraph - must be an array");
			throw new InvalidSPDXAnalysisException("Invalid type for deserializeGraph - must be an array");
		}
		Map<String, String> creationInfoIdToSpecVersion = findCreationInfos(graph);
		deserializedObjectUris.clear();

		// Second pass - create the top level objects in the graph
		Map<String, TypedValue> graphIdToTypedValue = new HashMap<>();
		for (JsonNode graphNode : graph) {
			JsonNode id = graphNode.has(SPDX_ID_PROP) ? graphNode.get(SPDX_ID_PROP) : graphNode.get("@id");
			if (Objects.nonNull(id)) {
				Optional<String> type = typeNodeToType(graphNode.get("type"));
				if (type.isPresent()) {
					// create the object so that it can be referenced during deserialization
					String specVersion = getSpecVersionFromNode(graphNode, creationInfoIdToSpecVersion, 
							SpdxModelFactory.getLatestSpecVersion());
					TypedValue tv = createTypedValueFromNode(id.asText(), type.get(), specVersion);
					modelStore.create(tv);
					graphIdToTypedValue.put(id.asText(), tv);
					if (!modelStore.isAnon(id.asText())) {
						nonAnonGraphItems.add(tv);
					}
				}
			} else {
				logger.warn("Missing ID for one of the SPDX objects in the graph");
			}
		}
		// create the nested objects with an ID so that they can be referenced from anywhere in the graph
		for (JsonNode graphNode : graph) {
			createNestedObjects(graphNode, getSpecVersionFromNode(graphNode, creationInfoIdToSpecVersion,
					SpdxModelFactory.getLatestSpecVersion()), graphIdToTypedValue);
		}

		// 3rd pass - deserialize the properties
		for (JsonNode graphNode : graph) {
			try {
				deserializeCoreObject(graphNode, SpdxModelFactory.getLatestSpecVersion(),
						creationInfoIdToSpecVersion, graphIdToTypedValue, false);
			} catch (GenerationException e) {
				throw new InvalidSPDXAnalysisException("Unable to open schema file");
			}
		}
		return nonAnonGraphItems;
	}
	

	/**
	 * Creates the objects with an ID (IRI or blank node identifier) nested in the properties of a node,
	 * so that they can be referenced before or after the place where they are defined
	 * @param node JSON node
	 * @param specVersion version of the spec for the nested objects
	 * @param graphIdToTypedValue map of JSON IDs to the objects created
	 * @throws InvalidSPDXAnalysisException on errors creating the objects
	 */
	private void createNestedObjects(JsonNode node, String specVersion,
			Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException {
		for (Entry<String, JsonNode> field : node.properties()) {
			if (NON_PROPERTY_FIELD_NAMES.contains(field.getKey())) {
				continue;
			}
			List<JsonNode> values = new ArrayList<>();
			if (field.getValue().isArray()) {
				field.getValue().forEach(values::add);
			} else {
				values.add(field.getValue());
			}
			for (JsonNode value : values) {
				if (!value.isObject()) {
					continue;
				}
				JsonNode id = value.has(SPDX_ID_PROP) ? value.get(SPDX_ID_PROP) : value.get("@id");
				if (Objects.nonNull(id) && id.isTextual() && value.has("type") &&
						!graphIdToTypedValue.containsKey(id.asText())) {
					boolean allowCustomType;
					try {
						allowCustomType = EXTENSION_PROP.equals(field.getKey()) ||
								isExtensionProperty(field.getKey(), specVersion);
					} catch (GenerationException e) {
						throw new InvalidSPDXAnalysisException("Unable to open schema file", e);
					}
					Optional<String> type = allowCustomType ? typeNodeToTypeOrCustomType(value.get("type"), specVersion) :
						typeNodeToType(value.get("type"));
					if (type.isPresent()) {
						TypedValue tv = createTypedValueFromNode(id.asText(), type.get(), specVersion);
						if (!modelStore.exists(tv.getObjectUri())) {
							modelStore.create(tv);
						}
						graphIdToTypedValue.put(id.asText(), tv);
					}
				}
				createNestedObjects(value, specVersion, graphIdToTypedValue);
			}
		}
	}

	/**
	 * @param id from the JSON-LD file
	 * @param type SPDX type
	 * @param specVersion version of the spec
	 * @return a TypedValue based on the id, type, and specVersion
	 * @throws InvalidSPDXAnalysisException on model errors
	 */
	private TypedValue createTypedValueFromNode(String id, String type,
			String specVersion) throws InvalidSPDXAnalysisException {
		String storeId;
		if (id.startsWith("_:")) {
			if (!jsonAnonToStoreAnon.containsKey(id)) {
				jsonAnonToStoreAnon.put(id, modelStore.getNextId(IdType.Anonymous));
			}
			storeId = jsonAnonToStoreAnon.get(id);
		} else {
			storeId = id;
		}
		return new TypedValue(storeId, type, specVersion);
	}

	/**
	 * @param graph Graph of SPDX elements
	 * @return creationInfo JSON IDs and spec versions
	 */
	private Map<String, String> findCreationInfos(JsonNode graph) {
		Map<String, String> retval = new HashMap<>();
		for (JsonNode graphNode : graph) {
			Optional<String> type = typeNodeToType(graphNode.get("type"));
			if (type.isPresent() && SpdxConstantsV3.CORE_CREATION_INFO.equals(type.get())) {
				JsonNode id = graphNode.has(SPDX_ID_PROP) ? graphNode.get(SPDX_ID_PROP) : graphNode.get("@id");
				if (graphNode.has(SPEC_VERSION_PROP) && Objects.nonNull(id)) {
					retval.put(id.asText(), graphNode.get(SPEC_VERSION_PROP).asText());
				} else {
					logger.warn("Unable to obtain spec version for a creation info: {}", Objects.isNull(id) ? "[no ID]" : id);
				}
			}
		}
		return retval;
	}

	/**
	 * @param node SPDX object node
	 * @param creationInfoIdToSpecVersion map of creation info IDs to spec versions
	 * @param defaultSpecVersion default to use if no spec information could be found
	 * @return the spec version
	 */
	String getSpecVersionFromNode(JsonNode node, Map<String, String> creationInfoIdToSpecVersion, String defaultSpecVersion) {
		if (node.has(SPEC_VERSION_PROP)) {
			return node.get(SPEC_VERSION_PROP).asText();
		} else if (node.has("creationInfo")) {
			JsonNode creationInfoNode = node.get("creationInfo");
			if (creationInfoNode.isObject()) {
				if (creationInfoNode.has(SPEC_VERSION_PROP)) {
					return creationInfoNode.get(SPEC_VERSION_PROP).asText();
				} else {
					logger.warn("Missing creation info object spec version");
					return defaultSpecVersion;
				}
			} else {
				String creationInfoId = creationInfoNode.asText();
				if (creationInfoIdToSpecVersion.containsKey(creationInfoId)) {
					return creationInfoIdToSpecVersion.get(creationInfoId);
				} else {
					logger.warn("Missing creation info string spec version");
					return defaultSpecVersion;
				}
			}
		} else {
			return defaultSpecVersion;
		}
	}

	/**
	 * Deserialize a core object into the modelStore
	 * @param node Node containing an SPDX core object
	 * @param defaultSpecVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @param allowCustomType if true, the object may have a type IRI not defined in the SPDX model
	 * @return TypedValue of the core object
	 * @throws InvalidSPDXAnalysisException on errors converting to SPDX
	 * @throws GenerationException on errors creating the schema
	 */
	private synchronized TypedValue deserializeCoreObject(JsonNode node, String defaultSpecVersion,
			Map<String, String> creationInfoIdToSpecVersion, Map<String, TypedValue> graphIdToTypedValue,
			boolean allowCustomType) throws InvalidSPDXAnalysisException, GenerationException {
		TypedValue tv = getOrCreateCoreObject(node, graphIdToTypedValue, defaultSpecVersion, creationInfoIdToSpecVersion,
				allowCustomType);
		// An object with an ID can appear more than once (e.g., inlined in several places).  The properties
		// of later occurrences are only added if the object does not already have a value for them,
		// so that collection values are not repeated.
		boolean alreadyDeserialized = !deserializedObjectUris.add(tv.getObjectUri());
		List<PropertyDescriptor> existingProperties = alreadyDeserialized ?
				modelStore.getPropertyValueDescriptors(tv.getObjectUri()) : Collections.emptyList();
		for (Entry<String, JsonNode> field: node.properties()) {
			if (!NON_PROPERTY_FIELD_NAMES.contains(field.getKey())) {
				PropertyDescriptor property;
				try {
					Optional<PropertyDescriptor> optDesc = jsonFieldNameToProperty(field.getKey(), tv.getSpecVersion());
					if (optDesc.isEmpty()) {
						throw new InvalidSPDXAnalysisException("No property descriptor for field "+field.getKey());
					}
					property = optDesc.get();
				} catch (GenerationException e) {
					throw new InvalidSPDXAnalysisException("Unable to convert a JSON field name to a property", e);
				}
				if (existingProperties.contains(property)) {
					continue;
				}
				if (field.getValue().isArray()) {
					for (JsonNode element : field.getValue()) {
						modelStore.addValueToCollection(tv.getObjectUri(), property, toStoredObject(field.getKey(), element, tv.getSpecVersion(),
								creationInfoIdToSpecVersion, graphIdToTypedValue));
					}
				} else {
					modelStore.setValue(tv.getObjectUri(), property, toStoredObject(field.getKey(), field.getValue(), tv.getSpecVersion(), 
							creationInfoIdToSpecVersion, graphIdToTypedValue));
				}
			}
		}
		return tv;
	}


	/**
	 * Fetches the typed value for the core object from the map if exists, otherwise create, add to map
	 * @param node JSON Node for the core object
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @param defaultSpecVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param allowCustomType if true, the object may have a type IRI not defined in the SPDX model
	 * @return existing or created TypedValue for the core object
	 * @throws InvalidSPDXAnalysisException on model exceptions
	 */
	private TypedValue getOrCreateCoreObject(JsonNode node,
			Map<String, TypedValue> graphIdToTypedValue, String defaultSpecVersion,
			Map<String, String> creationInfoIdToSpecVersion, boolean allowCustomType) throws InvalidSPDXAnalysisException {
		String jsonNodeId;
		if (node.has("@id")) {
			jsonNodeId = node.get("@id").asText();
		} else {
			jsonNodeId = node.has(SPDX_ID_PROP) ? node.get(SPDX_ID_PROP).asText() : null;
		}
		if (graphIdToTypedValue.containsKey(jsonNodeId)) {
			return graphIdToTypedValue.get(jsonNodeId);
		} else {
			// Need to create the object
			String id;
			Optional<String> type;
			String specVersion;
			if (Objects.isNull(jsonNodeId)) {
				id = modelStore.getNextId(IdType.Anonymous);
			} else if (jsonNodeId.startsWith("_:")) {
				if (!jsonAnonToStoreAnon.containsKey(jsonNodeId)) {
					jsonAnonToStoreAnon.put(jsonNodeId, modelStore.getNextId(IdType.Anonymous));
				}
				id = jsonAnonToStoreAnon.get(jsonNodeId);
			} else {
				id = jsonNodeId;
			}
			specVersion = getSpecVersionFromNode(node, creationInfoIdToSpecVersion, defaultSpecVersion);
			type = allowCustomType ? typeNodeToTypeOrCustomType(node.get("type"), specVersion) :
				typeNodeToType(node.get("type"));
			if (type.isEmpty()) {
				logger.error("Missing type for core object {}", node);
				throw new InvalidSPDXAnalysisException("Missing type for core object " + node);
			}
			TypedValue tv = new TypedValue(id, type.get(), specVersion);
			modelStore.create(tv);
			graphIdToTypedValue.put(id, tv);
			return tv;
		}
	}

	/**
	 * @param propertyName the name of the property in the JSON schema
	 * @param value JSON node containing an object to store in the modelStore
	 * @param specVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return an object suitable for storing in the model store
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on errors obtaining the schema
	 */
	private Object toStoredObject(String propertyName, JsonNode value, String specVersion,
			Map<String, String> creationInfoIdToSpecVersion, Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException, GenerationException {
		Optional<String> propertyType = getOrCreateSchema(specVersion).getPropertyType(propertyName);
		switch (value.getNodeType()) {
			case ARRAY:
				throw new InvalidSPDXAnalysisException("Can not convert a JSON array to a stored object");
			case BOOLEAN: {
				if (propertyType.isEmpty() || JsonLDSchema.BOOLEAN_TYPES.contains(propertyType.get())) {
					return value.asBoolean();
				} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
					return value.asText();
				} else {
					throw new InvalidSPDXAnalysisException("Type mismatch.  Expecting "+propertyType+" but was a JSON Boolean");
				}
			}
			case NULL: throw new InvalidSPDXAnalysisException("Can not convert a JSON NULL to a stored object");
			case NUMBER: {
				if (propertyType.isEmpty()) {
					// No schema type (e.g., an extension property) - preserve the JSON number
					return untypedJsonNumberToStoredValue(value);
				} else if (JsonLDSchema.INTEGER_TYPES.contains(propertyType.get())) {
					return jsonNumberToSpdxInteger(propertyName, value);
				} else if (JsonLDSchema.DOUBLE_TYPES.contains(propertyType.get())) {
					return checkSpdxDecimal(propertyName, value.asDouble());
				} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
					return value.asText();
				} else {
					throw new InvalidSPDXAnalysisException("Type mismatch.  Expecting "+propertyType+" but was a JSON Number");
				}
			}
			case OBJECT: {
				boolean extensionProperty = isExtensionProperty(propertyName, specVersion);
				if (extensionProperty && value.has("@value")) {
					// JSON-LD value object
					return jsonLdValueObjectToStoredObject(propertyName, value, specVersion,
							creationInfoIdToSpecVersion, graphIdToTypedValue);
				} else if (extensionProperty && value.has("@id") && value.size() == 1) {
					// JSON-LD node reference - an extension property has no type in the context
					// so the reference can not be written as a plain string
					return jsonStringToSpdxObject(value.get("@id"), specVersion, graphIdToTypedValue);
				} else {
					// Custom types are allowed where the SPDX model allows extensions and within
					// the values of extension properties
					return deserializeCoreObject(value, specVersion, creationInfoIdToSpecVersion, graphIdToTypedValue,
							extensionProperty || EXTENSION_PROP.equals(propertyName));
				}
			}
			case STRING:
				return jsonStringToStoredValue(propertyName, value, specVersion, graphIdToTypedValue);
			case BINARY:
			case MISSING:
			case POJO:
			default: throw new InvalidSPDXAnalysisException("Unsupported JSON node type: "+ value);
			}
	}

	/**
	 * The Java model holds SPDX integer properties as an Integer, but their XSD types (e.g.,
	 * xsd:nonNegativeInteger) are unbounded.  A valid value outside of the int range is kept
	 * exactly as an xsd:integer {@link TypedLiteral}: it is written back unchanged, and reading it
	 * through the model reports a type error instead of a wrong number.
	 *
	 * @param propertyName name of the SPDX integer property
	 * @param value JSON number
	 * @return an Integer, or an xsd:integer {@link TypedLiteral} if the value does not fit in an int
	 * @throws InvalidSPDXAnalysisException if the value is not an integer
	 */
	static Object jsonNumberToSpdxInteger(String propertyName, JsonNode value) throws InvalidSPDXAnalysisException {
		// Double.isFinite also rules out a huge exponent (e.g., 1e999999999) before it is expanded
		if (value.isIntegralNumber() || Double.isFinite(value.asDouble())) {
			try {
				return integerToStoredValue(value.decimalValue().toBigIntegerExact());
			} catch (ArithmeticException e) {
				// not an integer
			}
		}
		throw new InvalidSPDXAnalysisException("Invalid value " + value.asText() + " for the integer property " +
				propertyName + ": the value must be an integer");
	}

	/**
	 * @param propertyName name of the SPDX integer property
	 * @param text string value
	 * @return an Integer, or an xsd:integer {@link TypedLiteral} if the value does not fit in an int
	 * @throws InvalidSPDXAnalysisException if the value is not an integer
	 */
	static Object stringToSpdxInteger(String propertyName, String text) throws InvalidSPDXAnalysisException {
		try {
			return integerToStoredValue(new BigInteger(text.trim()));
		} catch (NumberFormatException e) {
			throw new InvalidSPDXAnalysisException("Invalid value " + text + " for the integer property " +
					propertyName + ": the value must be an integer");
		}
	}

	/**
	 * @param propertyName name of the SPDX decimal property
	 * @param value parsed value
	 * @return the value
	 * @throws InvalidSPDXAnalysisException if the value is not finite
	 */
	static double checkSpdxDecimal(String propertyName, double value) throws InvalidSPDXAnalysisException {
		if (!Double.isFinite(value)) {
			throw new InvalidSPDXAnalysisException("Invalid value " + value + " for the decimal property " +
					propertyName + ": the value must be a finite number");
		}
		return value;
	}

	/**
	 * Converts a JSON number without a type in the schema, such as the value of an extension
	 * property, following the JSON-LD 1.1 API (section 8.2): a number with a non-zero fractional
	 * part or an absolute value of at least 10^21 is an xsd:double, any other number is an xsd:integer
	 * <p>
	 * The decision is made on the decimal value of the node.  A node parsed as a double has already
	 * lost digits (e.g., 1e-400 is 0.0), so the JSON text should be parsed with
	 * {@code DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS}, as {@link JsonLDStore} does.
	 * </p>
	 * @param value JSON number
	 * @return an Integer if the value is an integer in the int range, a {@link TypedLiteral} with the
	 * datatype xsd:integer for other integers, otherwise a Double
	 */
	static Object untypedJsonNumberToStoredValue(JsonNode value) {
		if (value.isIntegralNumber()) {
			BigInteger integer = value.bigIntegerValue();
			if (new BigDecimal(integer).abs().compareTo(MIN_DOUBLE_MAGNITUDE) >= 0) {
				return value.asDouble();
			}
			return integerToStoredValue(integer);
		}
		double d = value.asDouble();
		if (!Double.isFinite(d)) {
			// outside of the double range (e.g., 1e400)
			return d;
		}
		// Decide on the decimal value rather than the double: 1e-400 has a non-zero fraction
		// even though it is 0 as a double
		BigDecimal decimal = value.decimalValue();
		if (decimal.abs().compareTo(MIN_DOUBLE_MAGNITUDE) < 0 && decimal.stripTrailingZeros().scale() <= 0) {
			return integerToStoredValue(decimal.toBigIntegerExact());
		}
		return d;
	}

	/**
	 * @param value integer value
	 * @return an Integer if the value fits, otherwise an xsd:integer {@link TypedLiteral} with every digit
	 */
	private static Object integerToStoredValue(BigInteger value) {
		if (value.bitLength() < Integer.SIZE) {
			return value.intValue();
		} else {
			return new TypedLiteral(value.toString(), XSD_INTEGER);
		}
	}

	/**
	 * @param propertyName name of the property in the JSON
	 * @param specVersion version of the spec
	 * @return true if the property is not defined in the SPDX JSON-LD context, i.e., it is an extension property
	 * @throws GenerationException on errors obtaining the schema
	 */
	private boolean isExtensionProperty(String propertyName, String specVersion) throws GenerationException {
		return getOrCreateSchema(specVersion).getPropertyDescriptor(propertyName).isEmpty();
	}

	/**
	 * Converts a JSON-LD value object (an object with an {@code @value}) to a stored value
	 * <p>
	 * A value object with an {@code @type} is stored as a {@link TypedLiteral} so that the
	 * lexical form and the datatype are kept.  A value object without an {@code @type} is
	 * stored the same way as its {@code @value}.
	 * </p>
	 * @param propertyName the name of the property in the JSON
	 * @param value JSON-LD value object
	 * @param specVersion version of the spec
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return an object suitable for storing in the model store
	 * @throws InvalidSPDXAnalysisException on unsupported or invalid value objects
	 * @throws GenerationException on errors obtaining the schema
	 */
	private Object jsonLdValueObjectToStoredObject(String propertyName, JsonNode value, String specVersion,
			Map<String, String> creationInfoIdToSpecVersion, Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException, GenerationException {
		if (value.has("@language")) {
			throw new InvalidSPDXAnalysisException("Language-tagged strings (@language) are not supported.  Property: "+propertyName);
		}
		for (Entry<String, JsonNode> field : value.properties()) {
			if (!"@value".equals(field.getKey()) && !"@type".equals(field.getKey())) {
				throw new InvalidSPDXAnalysisException("Unsupported key "+field.getKey()+" in JSON-LD value object for property "+propertyName);
			}
		}
		JsonNode literal = value.get("@value");
		if (!literal.isValueNode() || literal.isNull()) {
			throw new InvalidSPDXAnalysisException("Invalid @value in JSON-LD value object for property "+propertyName);
		}
		if (!value.has("@type")) {
			return toStoredObject(propertyName, literal, specVersion, creationInfoIdToSpecVersion, graphIdToTypedValue);
		}
		JsonNode datatypeNode = value.get("@type");
		if (!datatypeNode.isTextual() || datatypeNode.asText().startsWith("@")) {
			throw new InvalidSPDXAnalysisException("Unsupported @type "+datatypeNode+" in JSON-LD value object for property "+propertyName);
		}
		String datatype = getOrCreateSchema(specVersion).expandCompactIri(datatypeNode.asText());
		if (!isAbsoluteIri(datatype)) {
			throw new InvalidSPDXAnalysisException("The @type "+datatype+" in a JSON-LD value object must be an absolute IRI.  Property: "+propertyName);
		}
		if (COMPACT_IRI_PREFIXES.contains(datatype.substring(0, datatype.indexOf(':')))) {
			logger.warn("The datatype {} of property {} looks like a compact IRI, but the SPDX JSON-LD context does not define its prefix.  It is kept as written.",
					datatype, propertyName);
		}
		return new TypedLiteral(literalToLexicalForm(literal, datatype), datatype);
	}

	/**
	 * Converts the {@code @value} of a value object with a datatype to its lexical form following
	 * the JSON-LD 1.1 API (section 8.2)
	 * @param literal {@code @value} - a string, boolean, or number
	 * @param datatype datatype IRI
	 * @return the lexical form
	 */
	static String literalToLexicalForm(JsonNode literal, String datatype) {
		if (literal.isNumber()) {
			Object number = untypedJsonNumberToStoredValue(literal);
			if (XSD_DOUBLE.equals(datatype) || number instanceof Double) {
				return canonicalDouble(literal.asDouble());
			} else if (number instanceof TypedLiteral) {
				return ((TypedLiteral) number).getValue();
			} else {
				return number.toString();
			}
		}
		return literal.asText();
	}

	/**
	 * @param d value
	 * @return the canonical lexical form of an xsd:double, as used by the JSON-LD 1.1 API (e.g., 5.0E-1)
	 */
	static String canonicalDouble(double d) {
		if (Double.isNaN(d)) {
			return "NaN";
		} else if (Double.isInfinite(d)) {
			return d > 0 ? "INF" : "-INF";
		} else if (d == 0) {
			return 1 / d < 0 ? "-0.0E0" : "0.0E0";
		}
		BigDecimal decimal = new BigDecimal(Double.toString(d)).stripTrailingZeros();
		String digits = decimal.unscaledValue().abs().toString();
		int exponent = digits.length() - 1 - decimal.scale();
		return (decimal.signum() < 0 ? "-" : "") + digits.charAt(0) + "." +
				(digits.length() > 1 ? digits.substring(1) : "0") + "E" + exponent;
	}


	/**
	 * @param propertyName name of property in the JSON schema
	 * @param jsonValue string value
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return appropriate SPDX object based on the type associated with the propertyName
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on error getting JSON schemas
	 */
	private Object jsonStringToStoredValue(String propertyName, JsonNode jsonValue, String specVersion, 
			Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException, GenerationException {
		// A JSON string can represent an Element, another object (like CreatingInfo), an enumeration, an
		// individual value URL, an external URI
		JsonLDSchema schema = getOrCreateSchema(specVersion);
		if (schema.isSpdxObject(propertyName)) {
			return jsonStringToSpdxObject(jsonValue, specVersion, graphIdToTypedValue);
		} else if (schema.isEnum(propertyName)) {
			// we can assume that the @vocab points to the prefix for the enumerations
			Optional<String> vocab = schema.getVocab(propertyName);
			if (vocab.isEmpty()) {
				throw new InvalidSPDXAnalysisException("Missing vocabulary for enum property "+propertyName);
			}
			return new SimpleUriValue(vocab.get() + jsonValue.asText());
		} else {
			Optional<String> propertyType = schema.getPropertyType(propertyName);
			if (propertyType.isEmpty()) {
				logger.warn("Missing property type for value {}.  Defaulting to a string type", jsonValue);
				return jsonValue.asText();
			} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
				return jsonValue.asText();
			} else if (JsonLDSchema.DOUBLE_TYPES.contains(propertyType.get())) {
				try {
					return checkSpdxDecimal(propertyName, Double.parseDouble(jsonValue.asText()));
				} catch (NumberFormatException e) {
					throw new InvalidSPDXAnalysisException("Invalid value " + jsonValue.asText() +
							" for the decimal property " + propertyName + ": the value must be a number");
				}
			} else if (JsonLDSchema.INTEGER_TYPES.contains(propertyType.get())) {
				return stringToSpdxInteger(propertyName, jsonValue.asText());
			} else if (JsonLDSchema.BOOLEAN_TYPES.contains(propertyType.get())) {
				return Boolean.parseBoolean(jsonValue.asText());
			} else {
				throw new InvalidSPDXAnalysisException("Unknown type: "+propertyType.get()+" for property "+propertyName);
			}
		}
	}
	
	/**
	 * @param jsonValue string value
	 * @param specVersion version of the spec
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return SPDX object based on the type associated with the propertyName
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 */
	private Object jsonStringToSpdxObject(JsonNode jsonValue,
			String specVersion, Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException {
		if (graphIdToTypedValue.containsKey(jsonValue.asText())) {
			return graphIdToTypedValue.get(jsonValue.asText());
		} else if (jsonValue.asText().startsWith(SpdxConstantsV3.SPDX_LISTED_LICENSE_NAMESPACE)) {
			String licenseOrExceptionId = SpdxListedLicenseModelStore.objectUriToLicenseOrExceptionId(jsonValue.asText());
			if (ListedLicenses.getListedLicenses().isSpdxListedLicenseId(licenseOrExceptionId) ||
					ListedLicenses.getListedLicenses().isSpdxListedExceptionId(licenseOrExceptionId)) {
				return copyManager.copy(modelStore, ListedLicenses.getListedLicenses().getLicenseModelStore(),
						jsonValue.asText(), specVersion, null);
			} else {
				// treat as an external element
				return new SimpleUriValue(jsonValue.asText());
			}
		} else if (!jsonValue.asText().startsWith("_:")) {
			// either an individual URI or an external element
			return new SimpleUriValue(jsonValue.asText());
		} else {
			throw new InvalidSPDXAnalysisException("Unknown blank node reference "+jsonValue.asText());
		}
	}

	/**
	 * @param fieldName JSON name of the field
	 * @param specVersion version of the spec used for the JSON field name conversion
	 * @return Property descriptor associated with the JSON field name based on the Schema
	 * @throws GenerationException when we can not create a schema
	 */
	private Optional<PropertyDescriptor> jsonFieldNameToProperty(String fieldName,
																 String specVersion) throws GenerationException {
		JsonLDSchema schema = getOrCreateSchema(specVersion);
		Optional<PropertyDescriptor> retval = schema.getPropertyDescriptor(fieldName);
		if (retval.isPresent()) {
			return retval;
		}
		// we'll assume this is a URI for an extension property
		int lastPartIndex = fieldName.lastIndexOf('#');
		if (lastPartIndex < 0) {
			lastPartIndex = fieldName.lastIndexOf('/');
		}
		if (lastPartIndex < 0) {
			lastPartIndex = 0;
		}
		return Optional.of(new PropertyDescriptor(
				fieldName.substring(lastPartIndex+1), fieldName.substring(0, lastPartIndex+1)));

	}

	/**
	 * @param specVersion version of the spec
	 * @return a schema for the spec version supplied
	 * @throws GenerationException when we can not create a schema
	 */
	private JsonLDSchema getOrCreateSchema(String specVersion) throws GenerationException {
		JsonLDSchema schema = versionToSchema.get(specVersion);
		if (Objects.nonNull(schema)) {
			return schema;
		}
		try {
			schema = new JsonLDSchema(String.format("schema-v%s.json",  specVersion),
					String.format("spdx-context-v%s.jsonld",  specVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			versionToSchema.put(specVersion, schema);
			return schema;
		} catch (GenerationException e) {
			logger.warn("Unable to get a schema for spec version {}.  Trying latest spec version.", specVersion);
		}
		String latestVersion = SpdxModelFactory.getLatestSpecVersion();
		schema = versionToSchema.get(latestVersion);
		if (Objects.nonNull(schema)) {
			return schema;
		}
		try {
			schema = new JsonLDSchema(String.format("schema-v%s.json",  latestVersion),
					String.format("spdx-context-v%s.jsonld",  latestVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			versionToSchema.put(latestVersion, schema);
			return schema;
		} catch (GenerationException e) {
			logger.error("Unable to get JSON schema for latest version", e);
			throw e;
		}
	}

	/**
	 * @param typeNode node containing the type
	 * @return the SPDX type
	 */
	private Optional<String> typeNodeToType(JsonNode typeNode) {
		if (Objects.isNull(typeNode)) {
			return Optional.empty();
		}
		String jsonType = typeNode.asText();
		String retval;
		if (jsonType.contains("_")) {
			String[] typeParts = jsonType.split("_");
			String profile = JSON_PREFIX_TO_MODEL_PREFIX.get(JsonLDSchema.RESERVED_JAVA_WORDS.getOrDefault(typeParts[0], typeParts[0]));
			if (Objects.isNull(profile)) {
				return Optional.empty();
			}
			retval = profile + "." + JsonLDSchema.RESERVED_JAVA_WORDS.getOrDefault(typeParts[1], typeParts[1]);
		} else {
			retval = "Core." + JsonLDSchema.RESERVED_JAVA_WORDS.getOrDefault(jsonType, jsonType);
		}
		return ALL_SPDX_TYPES.contains(retval) ? Optional.of(retval) : Optional.empty();
	}

	/**
	 * Converts a type node to an SPDX type, or to a custom type if the type is an IRI
	 * outside the SPDX namespace
	 * <p>
	 * A custom type which has no class registered in the {@link ModelRegistry} is registered
	 * as a {@link GenericExtension} so that it can be stored and inflated.
	 * </p>
	 * @param typeNode node containing the type
	 * @param specVersion version of the spec
	 * @return the SPDX type or the custom type IRI
	 * @throws InvalidSPDXAnalysisException on errors registering the custom type
	 */
	private Optional<String> typeNodeToTypeOrCustomType(JsonNode typeNode, String specVersion) throws InvalidSPDXAnalysisException {
		Optional<String> spdxType = typeNodeToType(typeNode);
		if (spdxType.isPresent() || Objects.isNull(typeNode) || !typeNode.isTextual()) {
			return spdxType;
		}
		String customType;
		try {
			customType = getOrCreateSchema(specVersion).expandCompactIri(typeNode.asText());
		} catch (GenerationException e) {
			throw new InvalidSPDXAnalysisException("Unable to open schema file", e);
		}
		if (!isAbsoluteIri(customType) || customType.startsWith(SPDX_NAMESPACE_PREFIX)) {
			return Optional.empty();
		}
		// Use the default extension type of the registry rather than registering each type IRI found
		// in the input.  An application may register its own class for a type or its own default.
		ModelRegistry registry = ModelRegistry.getModelRegistry();
		if (Objects.isNull(registry.getDefaultExtensionType())) {
			registry.registerDefaultExtensionTypeIfAbsent(GenericExtension.class);
		}
		return Objects.isNull(registry.typeToClass(customType, specVersion)) ? Optional.empty() : Optional.of(customType);
	}


	/**
	 * @param value string to check
	 * @return true if the value is an absolute IRI (not a blank node identifier)
	 */
	private static boolean isAbsoluteIri(String value) {
		try {
			URI uri = new URI(value);
			return uri.isAbsolute() && !"_".equals(uri.getScheme());
		} catch (URISyntaxException e) {
			return false;
		}
	}

	/**
	 * Deserialize a single element into the modelStore
	 * @param elementNode element to deserialize
	 * @return the typedValue of the deserialized object
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on errors with the JSON schemas
	 */
	public TypedValue deserializeElement(JsonNode elementNode) throws GenerationException, InvalidSPDXAnalysisException {
		Map<String, TypedValue> mapIdToTypedValue = new HashMap<>();
		Map<String, String> creationInfoIdToSpecVersion = new HashMap<>();
		deserializedObjectUris.clear();
		
		String id = elementNode.has(SPDX_ID_PROP) ? elementNode.get(SPDX_ID_PROP).asText() : elementNode.get("@id").asText();
		if (Objects.nonNull(id)) {
			if (id.startsWith("_:")) {
				throw new InvalidSPDXAnalysisException("Can not serialize an anonymous (blank) element");
			}
			Optional<String> type = typeNodeToType(elementNode.get("type"));
			if (type.isEmpty()) {
				throw new InvalidSPDXAnalysisException("Missing type for element "+id);
			}
			String specVersion = getSpecVersionFromNode(elementNode, creationInfoIdToSpecVersion, 
					SpdxModelFactory.getLatestSpecVersion());
			TypedValue tv = new TypedValue(id, type.get(), specVersion);
			modelStore.create(tv);
			mapIdToTypedValue.put(id, tv);
			createNestedObjects(elementNode, specVersion, mapIdToTypedValue);
		}
		return deserializeCoreObject(elementNode, SpdxModelFactory.getLatestSpecVersion(), creationInfoIdToSpecVersion,
				mapIdToTypedValue, false);
	}

}
