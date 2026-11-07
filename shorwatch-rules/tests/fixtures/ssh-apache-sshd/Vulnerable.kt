package com.example.sftp

import org.apache.sshd.common.keyprovider.KeyPairProvider
import java.nio.file.Path
import org.apache.sshd.common.kex.BuiltinDHFactories
import org.apache.sshd.common.signature.BuiltinSignatures
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider

/** An embedded SFTP server with Apache MINA SSHD. */
class Vulnerable {
    fun server(hostKey: Path): SshServer = SshServer.setUpDefaultServer().apply {
        val keys = SimpleGeneratorHostKeyProvider(hostKey)
        keys.setAlgorithm("RSA")
        keyPairProvider = keys
    }

    fun algorithms(): List<Any> = listOf(
        BuiltinSignatures.rsaSHA512,
        BuiltinSignatures.nistp256,
        BuiltinSignatures.ed25519,
        BuiltinDHFactories.curve25519,
        BuiltinDHFactories.dhg14_256,
    )

    fun keyTypes(): List<String> = listOf(
        KeyPairProvider.SSH_RSA,
        KeyPairProvider.SSH_DSS,
        KeyPairProvider.SSH_ED25519,
        KeyPairProvider.ECDSA_SHA2_NISTP256,
    )
}
