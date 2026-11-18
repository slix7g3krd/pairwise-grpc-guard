from security.grpc_guard import (
    method_allowed,
    metadata_ok,
    stream_tenant_ok,
    deadline_ok,
    max_message_ok,
    peer_identity
)


def test_reflection():
    assert method_allowed('grpc.reflection.v1alpha.ServerReflection') is False

def test_method():
    assert method_allowed('UserService.Get') is True

def test_method_bad():
    assert method_allowed('Admin.Debug') is False

def test_metadata():
    assert metadata_ok({'sig': 'x'}, 'secret') is True

def test_spoof():
    assert metadata_ok({'user': 'admin'}, 'secret') is False

def test_stream():
    assert stream_tenant_ok('t1', 't1') is True

def test_stream_bad():
    assert stream_tenant_ok('t1', 't2') is False

def test_deadline():
    assert deadline_ok(30, 60) is True

def test_deadline_bad():
    assert deadline_ok(120, 60) is False

def test_size():
    assert max_message_ok(1024, 4096) is True

def test_size_bad():
    assert max_message_ok(8192, 4096) is False

def test_mtls():
    assert peer_identity({'mtls': True, 'peer': 'client'}) == 'client'

def test_no_mtls():
    assert peer_identity({'mtls': False, 'peer': 'client'}) is None

def test_empty():
    assert method_allowed('') is False

def test_error():
    assert 'stack' not in str(peer_identity({'mtls': True, 'peer': 'client'}))
