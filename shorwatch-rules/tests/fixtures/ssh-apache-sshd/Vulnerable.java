package com.example.sftp;

import java.nio.file.Path;
import java.util.List;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

/** An embedded SFTP server with Apache MINA SSHD. */
public class Vulnerable {
    SshServer server(Path hostKey) {
        SshServer server = SshServer.setUpDefaultServer();
        SimpleGeneratorHostKeyProvider keys = new SimpleGeneratorHostKeyProvider(hostKey);
        keys.setAlgorithm("RSA");
        server.setKeyPairProvider(keys);
        return server;
    }

    List<Object> algorithms() {
        return List.of(
                BuiltinSignatures.rsaSHA512,
                BuiltinSignatures.nistp256,
                BuiltinSignatures.ed25519,
                BuiltinDHFactories.curve25519,
                BuiltinDHFactories.dhg14_256);
    }
}
