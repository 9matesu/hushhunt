import pytest

from hushhunt.proxy_pool import ProxyPool


def test_proxy_pool_empty_returns_none():
    pool = ProxyPool([])
    assert pool.get_next_proxy() is None


def test_proxy_pool_rotates_proxies():
    proxies = ["http://proxy1:8080", "http://proxy2:8080", "http://proxy3:8080"]
    pool = ProxyPool(proxies)
    p1 = pool.get_next_proxy()
    p2 = pool.get_next_proxy()
    p3 = pool.get_next_proxy()
    p4 = pool.get_next_proxy()

    assert p1 == "http://proxy1:8080"
    assert p2 == "http://proxy2:8080"
    assert p3 == "http://proxy3:8080"
    assert p4 == "http://proxy1:8080"  # Wrapped around round-robin
