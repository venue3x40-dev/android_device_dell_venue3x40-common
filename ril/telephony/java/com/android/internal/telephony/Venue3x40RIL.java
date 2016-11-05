/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.telephony;

import static com.android.internal.telephony.RILConstants.*;

import android.content.Context;
import android.os.Parcel;

import com.android.internal.telephony.uicc.IccUtils;

/**
 * RIL customization for Dell Venue 3x40 devices
 *
 * {@hide}
 */
public class Venue3x40RIL extends RIL {

    //***** Constructors

    public Venue3x40RIL(Context context, int preferredNetworkType, int cdmaSubscription) {
        this(context, preferredNetworkType, cdmaSubscription, null);
    }

    public Venue3x40RIL(Context context, int preferredNetworkType,
            int cdmaSubscription, Integer instanceId) {
        super(context, preferredNetworkType, cdmaSubscription, instanceId);
    }

    //***** Private Methods

    @Override
    protected void
    processUnsolicited (Parcel p) {
        int response;
        Object ret;

        int dataPosition = p.dataPosition(); // save off position within the Parcel
        response = p.readInt();

        switch(response) {
            case RIL_UNSOL_OEM_HOOK_RAW:
                ret = responseRaw(p);
                // db00000001000000 when call is disconnected
                if (IccUtils.bytesToHexString((byte[]) ret).equals("db00000001000000")) {
                    p.setDataPosition(dataPosition);
                    p.writeInt(RIL_UNSOL_RESPONSE_CALL_STATE_CHANGED);
                }
                // Do not break
            default:
                // Rewind the Parcel
                p.setDataPosition(dataPosition);

                // Forward responses that we are not overriding to the super class
                super.processUnsolicited(p);
                return;
        }

    }

}
