package com.example.migrating;

import java.security.KeyPairGenerator;
import org.openquantumsafe.KeyEncapsulation;

public class Hybrid {
    Object keys() throws Exception {
        return KeyPairGenerator.getInstance("EC").generateKeyPair();
    }
}
