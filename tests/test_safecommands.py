import pytest

from hushhunt.safecommands import is_destructive


def test_blocks_wipe_rm():
    assert is_destructive("rm -rf /")
    assert is_destructive("rm -fr ~")
    assert is_destructive("rm -rf /etc")


def test_blocks_device_wipe_and_bombs():
    assert is_destructive("dd if=/dev/zero of=/dev/sda")
    assert is_destructive("mkfs.ext4 /dev/nvme0n1")
    assert is_destructive(":(){ :|:& };:")
    assert is_destructive("wipefs /dev/sda")


def test_blocks_shutdown():
    assert is_destructive("shutdown -h now")
    assert is_destructive("reboot")


def test_allows_inert_canaries_and_targeted_cleanup():
    assert not is_destructive("curl 'http://canary.example/hit?token=abc'")
    assert not is_destructive("rm /tmp/hushhunt-marker-file")
    assert not is_destructive("$(curl http://canary/x)")


def test_poc_runner_rejects_destructive_scripts():
    from hushhunt.poc import PoCContractError, run_poc

    class Dummy:
        def fetch(self, url, headers=None):
            raise AssertionError("must never reach execution")

    with pytest.raises(PoCContractError):
        run_poc("client.fetch('http://x')\nos.system('rm -rf /')\nresult['ok']=True",
                Dummy())                      # also import-blocked; belt+suspenders
    with pytest.raises(PoCContractError):
        run_poc("r = client.fetch('http://x')\n# escalation plan: mkfs /dev/sda\n"
                "result['ok'] = True", Dummy())
