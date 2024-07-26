/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.v3jsonldstore;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
import org.spdx.core.SimpleUriValue;
import org.spdx.core.TypedValue;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.PropertyDescriptor;

import com.fasterxml.jackson.databind.JsonNode;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * Class to manage deserializing SPDX 3.X JSON-LD
 * 
 * @author Gary O'Neall
 *
 */
public class JsonLDDeserializer {
	
	static final Logger logger = LoggerFactory.getLogger(JsonLDDeserializer.class);
	
	static final Set<String> ALL_SPDX_TYPES;
	static final Set<String> NON_PROPERTY_FIELD_NAMES;
	static final Map<String, String> JSON_PREFIX_TO_MODEL_PREFIX;
	
	static {
		Set<String> allSpdxTypes = new HashSet<>();
		Map<String, String> jsonPrefixToModelPrefix = new HashMap<>();
		Arrays.spliterator(SpdxConstantsV3.ALL_SPDX_CLASSES).forEachRemaining(c -> {
			allSpdxTypes.add(c);
			String nmspace = c.split("\\.")[0];
			jsonPrefixToModelPrefix.put(nmspace.toLowerCase(), nmspace);
		});
		ALL_SPDX_TYPES = Collections.unmodifiableSet(allSpdxTypes);
		JSON_PREFIX_TO_MODEL_PREFIX = Collections.unmodifiableMap(jsonPrefixToModelPrefix);
		
		Set<String> nonPropertyFieldNames = new HashSet<>();
		nonPropertyFieldNames.add("@id");
		nonPropertyFieldNames.add("spdxId");
		nonPropertyFieldNames.add("type");
		NON_PROPERTY_FIELD_NAMES = Collections.unmodifiableSet(nonPropertyFieldNames);
	}
	
	private IModelStore modelStore;
	private ConcurrentMap<String, String> jsonAnonToStoreAnon = new ConcurrentHashMap<>();
	private ConcurrentMap<String, JsonLDSchema> versionToSchema = new ConcurrentHashMap<>();

	/**
	 * @param modelStore Model store to deserialize the JSON text into
	 */
	public JsonLDDeserializer(IModelStore modelStore) {
		this.modelStore = modelStore;
	}

	/**
	 * Deserializes the JSON-LD graph into the modelStore
	 * @param graph Graph to deserialize
	 * @throws InvalidSPDXAnalysisException 
	 */
	public void deserializeGraph(JsonNode graph) throws InvalidSPDXAnalysisException {
		if (!graph.isArray()) {
			logger.error("Invalid type for deserializeGraph - must be an array");
			throw new InvalidSPDXAnalysisException("Invalid type for deserializeGraph - must be an array");
		}
		// First pass, we'll just collect creationInfo JSON IDs and spec versions
		Map<String, String> creationInfoIdToSpecVersion = new HashMap<>();
		Map<String, JsonNode> graphIdToJsonNode = new HashMap<>();
		for (Iterator<JsonNode> iter = graph.elements(); iter.hasNext(); ) {
			JsonNode graphNode = iter.next();
			Optional<String> type = typeNodeToType(graphNode.get("type"));
			if (graphNode.has("spdxId")) {
				graphIdToJsonNode.put(graphNode.get("spdxId").asText(), graphNode);
			}
			if (graphNode.has("@id")) {
				graphIdToJsonNode.put(graphNode.get("@id").asText(), graphNode);
			}
			if (type.isPresent() && "Core.CreationInfo".equals(type.get())) {
				if (graphNode.has("specVersion") && graphNode.has("@id")) {
					creationInfoIdToSpecVersion.put(graphNode.get("@id").asText(), 
							graphNode.get("specVersion").asText());
				}
			}
		}
		for (Iterator<JsonNode> iter = graph.elements(); iter.hasNext(); ) {
			try {
				deserializeCoreObject(iter.next(), SpdxModelFactory.getLatestSpecVersion(), 
						creationInfoIdToSpecVersion, graphIdToJsonNode);
			} catch (GenerationException e) {
				throw new InvalidSPDXAnalysisException("Unable to open schema file");
			}
		}
	}

	/**
	 * Deserialize a core object into the modelStore
	 * @param node Node containing an SPDX core object
	 * @param defaultSpecVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param graphIdToJsonNode map of all Object URIs and IDs stored in the graph
	 * @return TypedValue of the core object
	 * @throws InvalidSPDXAnalysisException on errors converting to SPDX
	 * @throws GenerationException on errors creating the schema
	 */
	private synchronized TypedValue deserializeCoreObject(JsonNode node, String defaultSpecVersion,
			Map<String, String> creationInfoIdToSpecVersion, Map<String, JsonNode> graphIdToJsonNode) throws InvalidSPDXAnalysisException, GenerationException {
		Optional<String> type = typeNodeToType(node.get("type"));
		if (!type.isPresent()) {
			logger.error("Missing type for core object " + node);
			throw new InvalidSPDXAnalysisException("Missing type for core object " + node);
		}
		String id = node.has("@id") ? node.get("@id").asText() : 
			node.has("spdxId") ? node.get("spdxId").asText() : null;
		if (Objects.isNull(id)) {
			id = modelStore.getNextId(IdType.Anonymous);
		} else if (id.startsWith("_:")) {
			if (!jsonAnonToStoreAnon.containsKey(id)) {
				jsonAnonToStoreAnon.put(id, modelStore.getNextId(IdType.Anonymous));
			}
			id = jsonAnonToStoreAnon.get(id);
		}
		String specVersion = defaultSpecVersion;
		if (node.has("creationInfo")) {
			JsonNode creationInfoNode = node.get("creationInfo");
			if (creationInfoNode.isObject() && creationInfoNode.has("specVersion")) {
				specVersion = creationInfoNode.get("specVersion").asText();
			} else {
				specVersion = creationInfoIdToSpecVersion.getOrDefault(creationInfoNode.asText(), specVersion);
			}
		} else if (SpdxConstantsV3.CORE_CREATION_INFO.equals(type.get()) && node.has("specVersion")) {
			specVersion = node.get("specVersion").asText();
		}
		TypedValue tv = new TypedValue(id, type.get(), specVersion);
		modelStore.create(tv);
		for (Iterator<Entry<String, JsonNode>> fields = node.fields(); fields.hasNext(); ) {
			Entry<String, JsonNode> field = fields.next();
			if (!NON_PROPERTY_FIELD_NAMES.contains(field.getKey())) {
				PropertyDescriptor property;
				try {
					Optional<PropertyDescriptor> optDesc = jsonFieledNameToProperty(field.getKey(), specVersion);
					if (!optDesc.isPresent()) {
						throw new InvalidSPDXAnalysisException("No property descriptor for field "+field.getKey());
					}
					property = optDesc.get();
				} catch (GenerationException e) {
					throw new InvalidSPDXAnalysisException("Unable to convrt a JSON field name to a property", e);
				}
				if (field.getValue().isArray()) {
					for (Iterator<JsonNode> elements = field.getValue().elements(); elements.hasNext(); ) {
						modelStore.addValueToCollection(id, property, toStoredObject(field.getKey(), elements.next(), specVersion,
								creationInfoIdToSpecVersion, graphIdToJsonNode));
					}
				} else {
					modelStore.setValue(id, property, toStoredObject(field.getKey(), field.getValue(), specVersion, 
							creationInfoIdToSpecVersion, graphIdToJsonNode));
				}
			}
		}
		return tv;
	}

	/**
	 * @param propertyName the name of the property in the JSON schema
	 * @param value JSON node containing an object to store in the modelStore
	 * @param specVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param graphIdToJsonNode map of all object URIs and IDs stored in the graph
	 * @return an object suitable for storing in the model store
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on errors obtaining the schema
	 */
	private Object toStoredObject(String propertyName, JsonNode value, String specVersion,
			Map<String, String> creationInfoIdToSpecVersion, Map<String, JsonNode> graphIdToJsonNode) throws InvalidSPDXAnalysisException, GenerationException {
		Optional<String> propertyType = getOrCreateSchema(specVersion).getPropertyType(propertyName);
		switch (value.getNodeType()) {
			case ARRAY:
				throw new InvalidSPDXAnalysisException("Can not convert a JSON array to a stored object");
			case BOOLEAN: {
				if (!propertyType.isPresent() || JsonLDSchema.BOOLEAN_TYPES.contains(propertyType.get())) {
					return value.asBoolean();
				} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
					return value.asText();
				} else {
					throw new InvalidSPDXAnalysisException("Type mismatch.  Expecting "+propertyType+" but was a JSON Boolean");
				}
			}
			case NULL: throw new InvalidSPDXAnalysisException("Can not convert a JSON NULL to a stored object");
			case NUMBER: {
				if (!propertyType.isPresent() || JsonLDSchema.INTEGER_TYPES.contains(propertyType.get())) {
					return value.asInt();
				} else if (JsonLDSchema.DOUBLE_TYPES.contains(propertyType.get())) {
					return value.asDouble();
				} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
					return value.asText();
				} else {
					throw new InvalidSPDXAnalysisException("Type mismatch.  Expecting "+propertyType+" but was a JSON Boolean");
				}
			}
			case OBJECT: return deserializeCoreObject(value, specVersion, creationInfoIdToSpecVersion, graphIdToJsonNode);
			case STRING:
				return jsonStringToStoredValue(propertyName, value, specVersion, graphIdToJsonNode);
			case BINARY:
			case MISSING:
			case POJO:
			default: throw new InvalidSPDXAnalysisException("Unsupported JSON node type: "+value.toString());
			}
	}

	/**
	 * @param propertyName name of property in the JSON schema
	 * @param jsonValue string value
	 * @param graphIdToJsonNode set of object URIs and IDs stored in the graph
	 * @return appropriate SPDX object based on the type associated with the propertyName
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on error getting JSON schemas
	 */
	private Object jsonStringToStoredValue(String propertyName, JsonNode jsonValue, String specVersion, Map<String, JsonNode> graphIdToJsonNode) throws InvalidSPDXAnalysisException, GenerationException {
		// A JSON string can represent an Element, another object (like CreatingInfo), an enumeration, an
		// individual value URL, an external URI
		JsonLDSchema schema = getOrCreateSchema(specVersion);
		Optional<String> propertyType = schema.getPropertyType(propertyName);
		if (!propertyType.isPresent()) {
			logger.warn("Missing property type for value "+jsonValue+".  Defaulting to a string type");
			return jsonValue.asText();
		} else if ("@id".equals(propertyType.get())) {
			// we can assume this refers to an SPDX object
			if (graphIdToJsonNode.containsKey(jsonValue.asText())) {
				JsonNode typeNode = graphIdToJsonNode.get(jsonValue.asText()).get("type");
				if (Objects.isNull(typeNode)) {
					throw new InvalidSPDXAnalysisException("Missing type for ID "+jsonValue.asText());
				}
				Optional<String> type = typeNodeToType(typeNode);
				if (!type.isPresent()) {
					throw new InvalidSPDXAnalysisException("Missing type in schema for ID "+jsonValue.asText());
				}
				return new TypedValue(jsonValue.asText(), type.get(), specVersion);
			} else {
				// either an individual URI or an external element
				return new SimpleUriValue(jsonValue.asText());
			}
		} else if ("@vocab".equals(propertyType.get())) {
			// we can assume that all @vocab types are enums
			Optional<String> vocab = schema.getVocab(propertyName);
			if (!vocab.isPresent()) {
				throw new InvalidSPDXAnalysisException("Missing vocabulary for enum property "+propertyName);
			}
			return new SimpleUriValue(vocab.get() + jsonValue.asText());
		} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
			return jsonValue.asText();
		} else if (JsonLDSchema.DOUBLE_TYPES.contains(propertyType.get())) {
			return Double.parseDouble(jsonValue.asText());
		} else if (JsonLDSchema.INTEGER_TYPES.contains(propertyType.get())) {
			return Integer.parseInt(jsonValue.asText());
		} else if (JsonLDSchema.BOOLEAN_TYPES.contains(propertyType.get())) {
			return Boolean.parseBoolean(jsonValue.asText());
		} else {
			throw new InvalidSPDXAnalysisException("Unknown type: "+propertyType.get()+" for property "+propertyName);
		}
		
	}

	/**
	 * @param fieldName JSON name of the field
	 * @param specVersion version of the spec used for the JSON field name conversion
	 * @return Property descriptor associated with the JSON field name based on the Schema
	 * @throws GenerationException when we can not create a schema
	 */
	private Optional<PropertyDescriptor> jsonFieledNameToProperty(String fieldName,
			String specVersion) throws GenerationException {
		JsonLDSchema schema = getOrCreateSchema(specVersion);
		return schema.getPropertyDescriptor(fieldName);
	}

	/**
	 * @param specVersion version of the spec
	 * @return a schema for the spec version supplie
	 * @throws GenerationException when we can not create a schema
	 */
	private JsonLDSchema getOrCreateSchema(String specVersion) throws GenerationException {
		JsonLDSchema schema = versionToSchema.get(specVersion);
		if (Objects.nonNull(schema)) {
			return schema;
		}
		try {
			schema = new JsonLDSchema(String.format("schema-v%s.json",  specVersion),
					String.format("spdx-context-v%s.jsonld",  specVersion));
			versionToSchema.put(specVersion, schema);
			return schema;
		} catch (GenerationException e) {
			logger.warn("Unable to get a schema for spec version "+specVersion+".  Trying latest spec version.");
		}
		String latestVersion = SpdxModelFactory.getLatestSpecVersion();
		schema = versionToSchema.get(latestVersion);
		if (Objects.nonNull(schema)) {
			return schema;
		}
		try {
			schema = new JsonLDSchema(String.format("schema-v%s.json",  latestVersion),
					String.format("spdx-context-v%s.jsonld",  latestVersion));
			versionToSchema.put(latestVersion, schema);
			return schema;
		} catch (GenerationException e) {
			logger.error("Unable to get JSON schema for latest version", e);
			throw e;
		}
	}

	/**
	 * @param typeNode node containing the type
	 * @return
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
	 * Deserialize a single element into the modelStore
	 * @param elementNode element to deserialize
	 * @return the typedValue of the deserialized object
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on errors with the JSON schemas
	 */
	public TypedValue deserializeElement(JsonNode elementNode) throws GenerationException, InvalidSPDXAnalysisException {
		Map<String, JsonNode> mapIdToJsonNode = new HashMap<>();
		String id = elementNode.has("@id") ? elementNode.get("@id").asText() : 
			elementNode.has("spdxId") ? elementNode.get("spdxId").asText() : null;
		if (Objects.nonNull(id)) {
			mapIdToJsonNode.put(id, elementNode);
		}
		return deserializeCoreObject(elementNode, SpdxModelFactory.getLatestSpecVersion(), new HashMap<>(), mapIdToJsonNode);
	}

}
