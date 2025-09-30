#include "Tpm.h"
#include "CreatePrimary_fp.h"
#include "transport.h"

#if CC_CreatePrimary  // Conditional expansion of this file

/*(See part 3 specification)
// Creates a primary or temporary object from a primary seed.
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       sensitiveDataOrigin is CLEAR when sensitive.data is an
//                              Empty Buffer; 'fixedTPM', 'fixedParent', or
//                              'encryptedDuplication' attributes are inconsistent
//                              between themselves or with those of the parent object;
//                              inconsistent 'restricted', 'decrypt', 'sign',
//                              'firmwareLimited', or 'svnLimited' attributes;
//                              attempt to inject sensitive data for an asymmetric
//                              key;
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM failed
//                              to derive the Firmware SVN Secret for the requested
//                              SVN.
//      TPM_RC_KDF              incorrect KDF specified for decrypting keyed hash
//                              object
//      TPM_RC_KEY              a provided symmetric key value is not allowed
//      TPM_RC_OBJECT_MEMORY    there is no free slot for the object
//      TPM_RC_SCHEME           inconsistent attributes 'decrypt', 'sign',
//                              'restricted' and key's scheme ID; or hash algorithm is
//                              inconsistent with the scheme ID for keyed hash object
//      TPM_RC_SIZE             size of public authorization policy or sensitive
//                              authorization value does not match digest size of the
//                              name algorithm; or sensitive data size for the keyed
//                              hash object is larger than is allowed for the scheme
//      TPM_RC_SYMMETRIC        a storage key with no symmetric algorithm specified;
//                              or non-storage key with symmetric algorithm different
//                              from TPM_ALG_NULL
//      TPM_RC_TYPE             unknown object type
TPM_RC
TPM2_CreatePrimary(CreatePrimary_In*  in,  // IN: input parameter list
                   CreatePrimary_Out* out  // OUT: output parameter list
)
{
    debug_breakpoint(0x51);
    TPM_RC       result = TPM_RC_SUCCESS;
    TPMT_PUBLIC* publicArea;
    DRBG_STATE   rand;
    OBJECT*      newObject;
    TPM2B_NAME   name;
    TPM2B_SEED   primary_seed;

    // Input Validation
    // Will need a place to put the result
    newObject = FindEmptyObjectSlot(&out->objectHandle);
    if(newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    // Get the address of the public area in the new object
    // (this is just to save typing)
    publicArea  = &newObject->publicArea;

    *publicArea = in->inPublic.publicArea;

    // Check attributes in input public area. CreateChecks() checks the things that
    // are unique to creation and then validates the attributes and values that are
    // common to create and load.
    debug_breakpoint(0x52);
    result = CreateChecks(
        NULL, in->primaryHandle, publicArea, in->inSensitive.sensitive.data.t.size);
    debug_breakpoint(0x53);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_CreatePrimary_inPublic);
    // Validate the sensitive area values
    debug_breakpoint(0x54);
    if(!AdjustAuthSize(&in->inSensitive.sensitive.userAuth, publicArea->nameAlg))
        return TPM_RCS_SIZE + RC_CreatePrimary_inSensitive;
    // Command output
    // Compute the name using out->name as a scratch area (this is not the value
    // that ultimately will be returned, then instantiate the state that will be
    // used as a random number generator during the object creation.
    // The caller does not know the seed values so the actual name does not have
    // to be over the input, it can be over the unmarshaled structure.
    debug_breakpoint(0x55);
    result = HierarchyGetPrimarySeed(in->primaryHandle, &primary_seed);
    if(result != TPM_RC_SUCCESS)
        return result;

    debug_breakpoint(0x56);
    result =
        DRBG_InstantiateSeeded(&rand,
                               &primary_seed.b,
                               PRIMARY_OBJECT_CREATION,
                               (TPM2B*)PublicMarshalAndComputeName(publicArea, &name),
                               &in->inSensitive.sensitive.data.b);
    debug_breakpoint(0x57);
    MemorySet(primary_seed.b.buffer, 0, primary_seed.b.size);
    debug_breakpoint(0x58);
    if(result == TPM_RC_SUCCESS)
    {
        newObject->attributes.primary = SET;
        if(HierarchyNormalizeHandle(in->primaryHandle) == TPM_RH_ENDORSEMENT)
            newObject->attributes.epsHierarchy = SET;
        debug_breakpoint(0x59);
        // Create the primary object.
        result = CryptCreateObject(
            newObject, &in->inSensitive.sensitive, (RAND_STATE*)&rand);
        DRBG_Uninstantiate(&rand);
    }
    if(result != TPM_RC_SUCCESS)
        return result;

    // Set the publicArea and name from the computed values
    out->outPublic.publicArea = newObject->publicArea;
    out->name                 = newObject->name;

    // Fill in creation data
    debug_breakpoint(0x5A);
    FillInCreationData(in->primaryHandle,
                       publicArea->nameAlg,
                       &in->creationPCR,
                       &in->outsideInfo,
                       &out->creationData,
                       &out->creationHash);

    // Compute creation ticket
    debug_breakpoint(0x5B);
    result = TicketComputeCreation(EntityGetHierarchy(in->primaryHandle),
                                   &out->name,
                                   &out->creationHash,
                                   &out->creationTicket);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Set the remaining attributes for a loaded object
    debug_breakpoint(0x5C);
    ObjectSetLoadedAttributes(newObject, in->primaryHandle);
    debug_breakpoint(0x5D);
    return result;
}

#endif  // CC_CreatePrimary