/*
 * Copyright (C) 2011 The Android Open Source Project
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
package com.android.emailcommon.service;

import com.android.emailcommon.service.PolicySet;

interface IPolicyService {
    boolean isActive(in PolicySet policies);
    void policiesRequired(long accountId);
    void updatePolicies(long accountId);
    void setAccountHoldFlag(long accountId, boolean newState);
    boolean isActiveAdmin();
    // This is about as oneway as you can get
    oneway void remoteWipe();
    boolean isSupported(in PolicySet policies);
    PolicySet clearUnsupportedPolicies(in PolicySet policies);
}