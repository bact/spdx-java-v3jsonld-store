/**
 * SPDX-FileCopyrightText: 2026 SPDX Contributors
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.annotation.Nullable;

import org.spdx.core.IModelCopyManager;
import org.spdx.core.IndividualUriValue;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.SpdxIdNotFoundException;
import org.spdx.core.TypedValue;
import org.spdx.library.model.v3_0_1.SpdxConstantsV3;
import org.spdx.library.model.v3_0_1.extension.Extension;
import org.spdx.storage.IModelStore;

/**
 * Model object for an extension whose type is not defined in the SPDX model
 * <p>
 * SPDX 3 lets anyone define a subclass of <code>Extension</code>, identified by
 * a full IRI. When a document uses such a type and no class has been registered
 * for it with {@link org.spdx.core.ModelRegistry#registerExtensionType(String, Class)},
 * the deserializer registers the type with this class. The type IRI and all
 * property values are kept in the model store, so the object can be verified,
 * copied, and serialized again without loss.
 * </p>
 * <p>
 * The same class is used for objects of an unknown type nested in the
 * property values of such an extension.
 * </p>
 * <p>
 * Objects of this class can only be created for an object which already exists
 * in the model store, since the type is read from the store.
 * </p>
 */
public class GenericExtension extends Extension {

	/**
	 * Constructor used by the {@link org.spdx.core.ModelRegistry} to inflate an extension
	 * @param modelStore Model store where the extension is stored
	 * @param objectUri URI or anonymous ID for the extension
	 * @param copyManager Copy manager for the extension - can be null if copying is not required
	 * @param create true if the extension is to be created - the object must already exist in the model store
	 * @param specVersion version of the SPDX spec - not used, the SPDX 3 model version is used
	 * @param idPrefix prefix to be used when generating new SPDX IDs
	 * @throws InvalidSPDXAnalysisException if the object does not exist in the model store
	 */
	public GenericExtension(IModelStore modelStore, String objectUri, @Nullable IModelCopyManager copyManager,
			boolean create, String specVersion, String idPrefix) throws InvalidSPDXAnalysisException {
		super(requireExisting(modelStore, objectUri), objectUri, copyManager, create, idPrefix);
	}

	/**
	 * @param modelStore model store
	 * @param objectUri URI or anonymous ID of the object
	 * @return the model store if the object exists in it
	 * @throws SpdxIdNotFoundException if the object does not exist in the model store
	 */
	private static IModelStore requireExisting(IModelStore modelStore, String objectUri) throws InvalidSPDXAnalysisException {
		if (!modelStore.getTypedValue(objectUri).isPresent()) {
			throw new SpdxIdNotFoundException("A generic extension can only be created for an existing object.  "
					+ objectUri + " does not exist in the model store.");
		}
		return modelStore;
	}

	/**
	 * @return the type IRI of the extension as stored in the model store
	 */
	@Override
	public String getType() {
		Optional<TypedValue> tv;
		try {
			tv = getModelStore().getTypedValue(getObjectUri());
		} catch (InvalidSPDXAnalysisException e) {
			tv = Optional.empty();
		}
		return tv.isPresent() ? tv.get().getType() : SpdxConstantsV3.EXTENSION_EXTENSION;
	}

	@Override
	public String toString() {
		return "Extension (" + getType() + "): " + getObjectUri();
	}

	/**
	 * The constraints of a custom extension are not known, so there is nothing to verify
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<IndividualUriValue> profiles) {
		return new ArrayList<>();
	}
}
