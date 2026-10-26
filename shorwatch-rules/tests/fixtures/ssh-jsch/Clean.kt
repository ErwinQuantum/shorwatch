package com.example.deploy

import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session

class Clean {
    fun configure(session: Session) {
        session.setConfig("StrictHostKeyChecking", "yes")
        // Names that only look alike: an RSA-free cipher list.
        JSch.setConfig("cipher.s2c", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com")
    }
}
