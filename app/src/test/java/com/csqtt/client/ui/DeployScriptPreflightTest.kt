// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

package com.csqtt.client.ui

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeployScriptPreflightTest {
    private fun script(): String {
        val candidates = listOf(
            File("app/src/main/assets/deploy.sh"),
            File("src/main/assets/deploy.sh"),
        )
        return candidates.first(File::isFile).readText()
    }

    private fun deployOperations(): String {
        val candidates = listOf(
            File("app/src/main/java/com/csqtt/client/ui/DeployOperations.kt"),
            File("src/main/java/com/csqtt/client/ui/DeployOperations.kt"),
        )
        return candidates.first(File::isFile).readText()
    }

    @Test
    fun `preflight performs working kernel probes`() {
        val deploy = script()
        assertTrue(deploy.contains("ip tuntap add dev \"\$probe_iface\" mode tun"))
        assertTrue(deploy.contains("setup_nat_and_firewall"))
        assertTrue(deploy.contains("iptables -w \"\$XT_WAIT\" -t nat -C POSTROUTING"))
        assertTrue(deploy.contains("probe_tun_support"))
        assertTrue(deploy.contains("prepare_uploaded_release()"))
        assertTrue(deploy.contains("run_platform_preflight"))
    }

    @Test
    fun `client cleans the old runtime before uploading the new binary`() {
        val deploy = script()
        val prepareBranch = deploy.substringAfter("prepare|--prepare|-p)").substringBefore("install|--install|-i|*)")
        val installBranch = deploy.substringAfter("install|--install|-i|*)")
        val uploadCheck = installBranch.indexOf("prepare_uploaded_release")
        val cleanup = prepareBranch.indexOf("csqtt_cleanup")
        val binary = installBranch.indexOf("setup_csqtt_binary")
        val preflight = installBranch.indexOf("run_platform_preflight")
        val firewall = installBranch.indexOf("setup_nat_and_firewall")
        assertTrue(uploadCheck >= 0)
        assertTrue(cleanup >= 0)
        assertTrue(binary >= 0)
        assertTrue(preflight > binary)
        assertTrue(firewall > binary)
        assertTrue(installBranch.contains("run_timed \"preflight\" run_platform_preflight"))
        assertTrue(prepareBranch.contains("CSQTT_DEPLOY_READY_FOR_UPLOAD"))
        assertTrue(installBranch.contains("local total_started=\$SECONDS\n            detect_os\n            require_runtime_tools"))

        val client = deployOperations()
        assertTrue(client.indexOf("bash /tmp/deploy.sh prepare") < client.indexOf("/tmp/.csqtt-upload-server"))
        assertTrue(client.indexOf("/tmp/.csqtt-upload-server") < client.indexOf("bash /tmp/deploy.sh install"))
    }

    @Test
    fun `activation uses direct runtime paths and has no staged candidate`() {
        val deploy = script()
        assertTrue(deploy.contains("readonly UPLOAD_BINARY=\"/tmp/.csqtt-upload-server\""))
        assertTrue(deploy.contains("install -m 0755 \"\$UPLOAD_BINARY\" /usr/local/bin/csqtt"))
        assertTrue(deploy.contains("install -m 0600 \"\$UPLOAD_ENV_FILE\" \"\$CSQTT_ENV_FILE\""))
        assertTrue(deploy.contains("rm -f /usr/local/bin/csqtt"))
        assertTrue(deploy.contains("rm -rf /usr/local/lib/csqtt"))
        assertTrue(deploy.contains("clear_runtime_config_preserving_database()"))
        assertFalse(deploy.contains("csqtt.next.XXXXXX"))
        assertFalse(deploy.contains("csqtt-stage"))
        assertFalse(deploy.contains("verify_staged_release"))
        assertTrue(deploy.contains("CSQTT_DEPLOY_READY_FOR_UPLOAD"))
        assertTrue(deploy.contains("probe_tun_support"))
    }

    @Test
    fun `redeploy removes old runtime config but preserves SQLite and its WAL files`() {
        val deploy = script()
        assertTrue(deploy.contains("readonly CSQTT_DATABASE_FILE=\"csqtt.db\""))
        assertTrue(deploy.contains("readonly CSQTT_DATABASE_WAL_FILE=\"csqtt.db-wal\""))
        assertTrue(deploy.contains("readonly CSQTT_DATABASE_SHM_FILE=\"csqtt.db-shm\""))
        assertTrue(deploy.contains("clear_runtime_config_preserving_database"))
        assertTrue(deploy.contains("\"\$CSQTT_DATABASE_FILE\"|\"\$CSQTT_DATABASE_WAL_FILE\"|\"\$CSQTT_DATABASE_SHM_FILE\"|\"\$CSQTT_LEGACY_MIGRATION_JSON\"|\"\$CSQTT_LEGACY_MIGRATION_IMPORTED_JSON\"|web_cert.pem|web_key.pem|letsencrypt-ip.env) continue"))
        assertFalse(deploy.contains("find \"\$CSQTT_CONFIG_DIR\" -mindepth 1 -maxdepth 1"))
    }

    @Test
    fun `docker uses minimal capabilities and repeats probes inside container`() {
        val deploy = script()
        assertTrue(deploy.contains("--cap-drop ALL"))
        assertTrue(deploy.contains("--cap-add NET_ADMIN"))
        assertTrue(deploy.contains("--cap-add NET_RAW"))
        assertTrue(deploy.contains("--device /dev/net/tun:/dev/net/tun"))
        assertTrue(deploy.contains("--security-opt seccomp=unconfined"))
        assertTrue(deploy.contains("probe_docker_runtime"))
        assertTrue(deploy.split("--cap-drop ALL").size >= 3)
        assertTrue(deploy.contains("COPY network-up.sh /usr/local/lib/csqtt/network-up.sh"))
        assertTrue(deploy.contains("exec /usr/local/bin/csqtt \\\"\$@\\\""))
        assertTrue(deploy.contains("write_network_helper \"\$context_dir/network-up.sh\""))
    }

    @Test
    fun `web health probe accepts the panel's unauthenticated response without creating sessions`() {
        val deploy = script()
        assertTrue(deploy.contains("200|301|302|401"))
        assertTrue(deploy.contains("${'$'}{scheme}://127.0.0.1:${'$'}{WEB_PORT}/"))
        assertFalse(deploy.contains("--data-binary @-"))
        assertFalse(deploy.contains("/api/login"))
        assertFalse(deploy.contains("NETWORK_READY_STAMP"))
    }

    @Test
    fun `configured network is verified after applying rules and after startup`() {
        val deploy = script()
        assertTrue(deploy.contains("verify_configured_network()"))
        assertTrue(deploy.split("verify_configured_network").size >= 4)
        assertTrue(deploy.contains("-j MASQUERADE >/dev/null 2>&1"))
        assertTrue(deploy.contains("-j TCPMSS --clamp-mss-to-pmtu 2>/dev/null"))
    }

    @Test
    fun `web panel prefers renewable trusted IP TLS with self signed fallback`() {
        val deploy = script()
        assertTrue(deploy.contains("--preferred-profile shortlived"))
        assertTrue(deploy.contains("--ip-address \"\$public_ip\""))
        assertTrue(deploy.contains("--force-renewal"))
        assertTrue(deploy.contains("openssl x509 -noout -checkend \"\$LE_RENEW_BEFORE_SECONDS\""))
        assertTrue(deploy.contains("OnUnitInactiveSec=6h"))
        assertTrue(deploy.contains("fw_add_input_tcp \"\$LE_HTTP_PORT\""))
        assertTrue(deploy.contains("web_cert.pem|web_key.pem|letsencrypt-ip.env"))
        assertTrue(deploy.contains("systemctl kill --kill-who=main --signal USR1 csqtt"))
        assertTrue(deploy.contains("docker kill --signal USR1 csqtt"))
        assertTrue(deploy.contains("issuer=\"\${issuer#issuer=}\""))
        assertTrue(deploy.contains("subject=\"\${subject#subject=}\""))
        assertTrue(deploy.contains("! python3 -c 'import ensurepip'"))
        assertTrue(deploy.contains("apt) python_packages=(python3 python3-venv)"))
        assertTrue(deploy.contains("pkg_install_with_refresh()"))
        assertTrue(deploy.contains("pkg_install_with_refresh \"\${python_packages[@]}\""))
        assertTrue(deploy.contains("local ip=\"\$1\" first second third fourth value"))
        assertTrue(deploy.contains("grep '^csqtp' || true"))
        assertTrue(deploy.contains("self-signed fallback"))
    }

    @Test
    fun `certificate ownership keeps user TLS untouched and renews only CSQTT certificates`() {
        val deploy = script()
        assertTrue(deploy.contains("certificate_is_csqtt_rcgen()"))
        assertTrue(deploy.contains("certificate_is_csqtt_letsencrypt()"))
        assertTrue(deploy.contains("web_certificate_is_csqtt_managed()"))
        assertTrue(deploy.contains("web_certificate_is_user_managed()"))
        assertTrue(deploy.contains("CN=rcgen self signed cert"))
        assertTrue(deploy.contains("O=Let's Encrypt"))
        assertTrue(deploy.contains("IP Address:\${saved_ip}"))
        assertTrue(deploy.contains("rm -f -- \"\$CSQTT_LE_STATE_FILE\""))
        assertTrue(deploy.contains("disable_letsencrypt_renewal_timer"))
        assertTrue(deploy.contains("CSQTT не изменяет его и отключает собственное продление"))
    }
}
