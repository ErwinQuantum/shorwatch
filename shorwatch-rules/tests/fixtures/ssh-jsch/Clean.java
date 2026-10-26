package com.example.deploy;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

public class Clean {
    void configure(Session session) {
        session.setConfig("StrictHostKeyChecking", "yes");
        // Names that only look alike: an RSA-free cipher list.
        JSch.setConfig("cipher.s2c", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com");
    }
}
