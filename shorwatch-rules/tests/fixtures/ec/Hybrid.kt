package com.example.migrating

import java.security.KeyPairGenerator
import org.openquantumsafe.KeyEncapsulation

class Hybrid {
    fun keys(): Any = KeyPairGenerator.getInstance("EC").generateKeyPair()
}
