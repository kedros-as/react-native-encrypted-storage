package com.emeraldsanto.encryptedstorage;

import com.facebook.react.BaseReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.module.model.ReactModuleInfoProvider;

import java.util.Collections;

public class RNEncryptedStoragePackage extends BaseReactPackage {

    @Override
    public NativeModule getModule(String name, ReactApplicationContext reactContext) {
        if (name.equals(RNEncryptedStorageModule.NAME)) {
            return new RNEncryptedStorageModule(reactContext);
        }

        return null;
    }

    @Override
    public ReactModuleInfoProvider getReactModuleInfoProvider() {
        return () -> Collections.singletonMap(
            RNEncryptedStorageModule.NAME,
            new ReactModuleInfo(
                RNEncryptedStorageModule.NAME,
                RNEncryptedStorageModule.NAME,
                false,
                false,
                false,
                true
            )
        );
    }
}
