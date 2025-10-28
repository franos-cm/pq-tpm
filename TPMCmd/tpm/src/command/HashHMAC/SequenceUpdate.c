#include "Tpm.h"
#include "SequenceUpdate_fp.h"
#if ALG_DILITHIUM
#  include "private/DilithiumSequence.h"
#  include "platform_interface/tpm_to_platform_interface.h"
#endif

#if CC_SequenceUpdate  // Conditional expansion of this file

/*(See part 3 specification)
// This function is used to add data to a sequence object.
*/
//  Return Type: TPM_RC
//      TPM_RC_MODE             'sequenceHandle' does not reference a hash or HMAC
//                              sequence object
TPM_RC
TPM2_SequenceUpdate(SequenceUpdate_In* in  // IN: input parameter list
)
{
    OBJECT*      object;
    HASH_OBJECT* hashObject;

    // Input Validation

    // Get sequence object pointer
    object     = HandleToObject(in->sequenceHandle);
    hashObject = (HASH_OBJECT*)object;

    // Check that referenced object is a sequence object.
    if(!ObjectIsSequence(object))
        return TPM_RCS_MODE + RC_SequenceUpdate_sequenceHandle;

#  if ALG_DILITHIUM
    if(object->attributes.dlhsSeq == SET)
    {
        DLHS_STATE* ds = &hashObject->state.dlhsState;
        if(in->buffer.t.size == 0 || in->buffer.t.size > ds->remaining)
            return TPM_RCS_SIZE + RC_SequenceUpdate_buffer;

        int prc = _plat__Dilithium_Update(
            ds->ctx_id, in->buffer.t.buffer, in->buffer.t.size);
        if(prc != 0)
            return TPM_RC_FAILURE;

        ds->remaining -= in->buffer.t.size;
        return TPM_RC_SUCCESS;
    }
    if(object->attributes.dlhvSeq == SET)
    {
        DLHV_STATE* ds = &hashObject->state.dlhvState;
        if(in->buffer.t.size == 0 || in->buffer.t.size > ds->remaining)
            return TPM_RCS_SIZE + RC_SequenceUpdate_buffer;

        int prc = _plat__Dilithium_Update(
            ds->ctx_id, in->buffer.t.buffer, in->buffer.t.size);
        if(prc != 0)
            return TPM_RC_FAILURE;

        // Update the ticket hash in parallel (for TPMT_TK_VERIFIED)
        CryptDigestUpdate(&ds->ticketHash, in->buffer.t.size, in->buffer.t.buffer);

        ds->remaining -= in->buffer.t.size;
        return TPM_RC_SUCCESS;
    }
#  endif  // ALG_DILITHIUM

    // Internal Data Update
    if(object->attributes.eventSeq == SET)
    {
        // Update event sequence object
        UINT32 i;
        for(i = 0; i < HASH_COUNT; i++)
        {
            // Update sequence object
            CryptDigestUpdate2B(&hashObject->state.hashState[i], &in->buffer.b);
        }
    }
    else
    {
        // Update hash/HMAC sequence object
        if(hashObject->attributes.hashSeq == SET)
        {
            // Is this the first block of the sequence
            if(hashObject->attributes.firstBlock == CLEAR)
            {
                // If so, indicate that first block was received
                hashObject->attributes.firstBlock = SET;

                // Check the first block to see if the first block can contain
                // the TPM_GENERATED_VALUE.  If it does, it is not safe for
                // a ticket.
                if(TicketIsSafe(&in->buffer.b))
                    hashObject->attributes.ticketSafe = SET;
            }
            // Update sequence object hash/HMAC stack
            CryptDigestUpdate2B(&hashObject->state.hashState[0], &in->buffer.b);
        }
        else if(object->attributes.hmacSeq == SET)
        {
            // Update sequence object HMAC stack
            CryptDigestUpdate2B(&hashObject->state.hmacState.hashState,
                                &in->buffer.b);
        }
    }
    return TPM_RC_SUCCESS;
}

#endif  // CC_SequenceUpdate