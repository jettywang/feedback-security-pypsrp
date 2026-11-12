# -*- coding: utf-8 -*-
"""
Security regression tests for disconnected shell reconnection.

A host may expose multiple PowerShell endpoints on the same WSMan service
(for example a constrained JEA endpoint and the normal Microsoft.PowerShell
endpoint). When a connection drops and the shells are rediscovered through
WSMan enumeration, pypsrp must bind each ShellId back to the resource URI the
server reported for that shell. It must not replay a ShellId against a
different endpoint or accept ambiguous/mismatched enumeration data.

The fake WSMan below records the (action, resource URI, ShellId selectors)
triple of every request so the actual target of Enumerate/Connect/Reconnect
and Command calls can be asserted.
"""

import typing
import uuid
import xml.etree.ElementTree as ET

import pytest

from pypsrp.complex_objects import RunspacePoolState
from pypsrp.exceptions import InvalidRunspacePoolConnectionError
from pypsrp.powershell import RunspacePool
from pypsrp.wsman import NAMESPACES, WSManAction

JEA_URI = "http://schemas.microsoft.com/powershell/Constrained.JEA"
DEFAULT_URI = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
SHELL_ENUM_URI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
COMMAND_ENUM_URI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"

JEA_SHELL_ID = "11111111-1111-1111-1111-111111111111"
DEFAULT_SHELL_ID = "22222222-2222-2222-2222-222222222222"


def _body(body_child: ET.Element) -> ET.Element:
    s = NAMESPACES["s"]
    envelope = ET.Element("{%s}Envelope" % s)
    header = ET.SubElement(envelope, "{%s}Header" % s)
    ET.SubElement(header, "{%s}RelatesTo" % NAMESPACES["wsa"]).text = "uuid:%s" % str(uuid.uuid4()).upper()
    body = ET.SubElement(envelope, "{%s}Body" % s)
    body.append(body_child)
    # WSMan.enumerate/connect/... return the s:Body element directly.
    return body


class FakeWSMan:
    """Minimal WSMan stand-in that answers shell/command enumeration and the
    reconnect/connect actions while recording every request target."""

    def __init__(self, shell_entries: typing.List[ET.Element], command_ids: typing.Dict[str, typing.List[str]] = None):
        self.shell_entries = shell_entries
        self.command_ids = command_ids or {}
        self.calls: typing.List[typing.Dict[str, typing.Any]] = []
        self.max_payload_size = 150000

    def _record(self, action: str, resource_uri: str, selector_set) -> None:
        selectors = {}
        if selector_set is not None:
            for name, value, _ in selector_set.values:
                selectors[name] = value
        self.calls.append({"action": action, "resource_uri": resource_uri, "selectors": selectors})

    def enumerate(self, resource_uri, resource=None, option_set=None, selector_set=None, timeout=None):
        self._record(WSManAction.ENUMERATE, resource_uri, selector_set)

        if resource_uri == SHELL_ENUM_URI:
            response = ET.Element("{%s}EnumerateResponse" % NAMESPACES["wsen"])
            items = ET.SubElement(response, "{%s}Items" % NAMESPACES["wsman"])
            for entry in self.shell_entries:
                items.append(entry)
            return _body(response)

        if resource_uri == COMMAND_ENUM_URI:
            shell_id = None
            if selector_set is not None:
                shell_id = selector_set.values[0][1]
            else:
                # The ShellId filter is carried in the request body's
                # wsman:Filter/wsman:SelectorSet when enumerating commands.
                filter_selector = resource.find(
                    "wsman:Filter/wsman:SelectorSet/wsman:Selector[@Name='ShellId']", NAMESPACES
                )
                if filter_selector is not None:
                    shell_id = filter_selector.text
            response = ET.Element("{%s}EnumerateResponse" % NAMESPACES["wsen"])
            items = ET.SubElement(response, "{%s}Items" % NAMESPACES["wsman"])
            for command_id in self.command_ids.get(shell_id, []):
                command = ET.SubElement(items, "{%s}Command" % NAMESPACES["rsp"])
                ET.SubElement(command, "{%s}CommandId" % NAMESPACES["rsp"]).text = command_id
            return _body(response)

        raise AssertionError("Unexpected enumeration URI %s" % resource_uri)

    def reconnect(self, resource_uri, resource=None, option_set=None, selector_set=None, timeout=None):
        self._record(WSManAction.RECONNECT, resource_uri, selector_set)
        response = ET.Element("{%s}ReconnectResponse" % NAMESPACES["rsp"])
        return _body(response)

    def connect(self, resource_uri, resource=None, option_set=None, selector_set=None, timeout=None):
        self._record(WSManAction.CONNECT, resource_uri, selector_set)
        # Mirror a host that returns the endpoint reference parameters.
        response = ET.Element("{%s}ConnectResponse" % NAMESPACES["rsp"])
        connect_response = ET.SubElement(response, "{%s}connectResponseXml" % NAMESPACES["pwsh"])
        connect_response.text = ""
        return _body(response)

    def command(self, resource_uri, resource, option_set=None, selector_set=None, timeout=None):
        self._record(WSManAction.COMMAND, resource_uri, selector_set)
        response = ET.Element("{%s}CommandResponse" % NAMESPACES["rsp"])
        ET.SubElement(response, "{%s}CommandId" % NAMESPACES["rsp"]).text = str(uuid.uuid4()).upper()
        return _body(response)


def make_shell(
    shell_id: str,
    resource_uri: str,
    *,
    include_reference: bool = False,
    extra_selectors=None,
) -> ET.Element:
    shell = ET.Element("{%s}Shell" % NAMESPACES["rsp"])
    ET.SubElement(shell, "{%s}ShellId" % NAMESPACES["rsp"]).text = shell_id
    ET.SubElement(shell, "{%s}ResourceUri" % NAMESPACES["rsp"]).text = resource_uri
    ET.SubElement(shell, "{%s}State" % NAMESPACES["rsp"]).text = "Disconnected"
    if include_reference:
        ref_params = ET.SubElement(shell, "{%s}ReferenceParameters" % NAMESPACES["wsa"])
        selector_set = ET.SubElement(ref_params, "{%s}SelectorSet" % NAMESPACES["wsman"])
        selectors = [("ShellId", shell_id)] + list(extra_selectors or [])
        for name, value in selectors:
            ET.SubElement(selector_set, "{%s}Selector" % NAMESPACES["wsman"], Name=name).text = value
    return shell


def targets(fake: FakeWSMan) -> typing.List[typing.Tuple[str, str, str]]:
    return [
        (call["action"].rsplit("/", 1)[-1], call["resource_uri"], call["selectors"].get("ShellId"))
        for call in fake.calls
    ]


def test_enumeration_binds_shell_to_reported_resource_uri():
    # Two endpoints on the same host with interleaved selector ordering.
    shells = [
        make_shell(DEFAULT_SHELL_ID, DEFAULT_URI),
        make_shell(JEA_SHELL_ID, JEA_URI),
    ]
    fake = FakeWSMan(shells)

    pools = RunspacePool.get_runspace_pools(fake)
    assert len(pools) == 2

    by_id = {pool.shell.id: pool for pool in pools}
    assert by_id[JEA_SHELL_ID].shell.resource_uri == JEA_URI
    assert by_id[DEFAULT_SHELL_ID].shell.resource_uri == DEFAULT_URI
    for pool in pools:
        assert pool.state == RunspacePoolState.DISCONNECTED
        assert pool.shell._selector_set is not None
        assert pool.shell._selector_set.values[0] == ("ShellId", pool.shell.id, {})


def test_new_client_connect_uses_constrained_endpoint():
    shells = [make_shell(JEA_SHELL_ID, JEA_URI, include_reference=True)]
    fake = FakeWSMan(shells, command_ids={JEA_SHELL_ID: []})

    pool = RunspacePool.get_runspace_pools(fake)[0]
    # The fake host does not run PSRP; stub the fragment parsing and receive
    # loop and mirror the state transition a successful connect produces.
    pool._parse_responses = lambda fragments: None
    pool._receive = lambda: setattr(pool, "state", RunspacePoolState.OPENED)
    pool.connect()

    connect_calls = [c for c in targets(fake) if c[0] == "Connect"]
    assert connect_calls == [("Connect", JEA_URI, JEA_SHELL_ID)]
    # No request may ever carry the JEA ShellId against the default endpoint.
    assert all(not (uri == DEFAULT_URI and shell_id == JEA_SHELL_ID) for _, uri, shell_id in targets(fake))
    assert pool.state == RunspacePoolState.OPENED


def test_existing_client_reconnect_keeps_constrained_endpoint_and_selectors():
    shells = [make_shell(JEA_SHELL_ID, JEA_URI, include_reference=True, extra_selectors=[("Endpoint", "jea")])]
    fake = FakeWSMan(shells)

    pool = RunspacePool.get_runspace_pools(fake)[0]
    # Simulate a reconnect by the same client (the shell object already holds
    # the authoritative selector set from enumeration).
    pool._new_client = False
    pool.connect()

    reconnect_calls = [c for c in targets(fake) if c[0] == "Reconnect"]
    assert reconnect_calls == [("Reconnect", JEA_URI, JEA_SHELL_ID)]
    recorded = next(call for call in fake.calls if call["action"] == WSManAction.RECONNECT)
    assert recorded["selectors"] == {"ShellId": JEA_SHELL_ID, "Endpoint": "jea"}
    assert pool.state == RunspacePoolState.OPENED


def test_command_after_reconnect_targets_original_endpoint():
    shells = [make_shell(JEA_SHELL_ID, JEA_URI)]
    fake = FakeWSMan(shells)

    pool = RunspacePool.get_runspace_pools(fake)[0]
    pool._new_client = False
    pool.connect()

    # A raw WinRS command on the reconnected shell must reuse the bound URI and
    # ShellId selector rather than falling back to the default endpoint.
    pool.shell.command("powershell.exe", [])
    command_calls = [c for c in targets(fake) if c[0] == "Command"]
    assert command_calls == [("Command", JEA_URI, JEA_SHELL_ID)]


def test_resource_uri_filter_skips_non_matching_endpoint():
    shells = [
        make_shell(DEFAULT_SHELL_ID, DEFAULT_URI),
        make_shell(JEA_SHELL_ID, JEA_URI),
    ]
    fake = FakeWSMan(shells)

    pools = RunspacePool.get_runspace_pools(fake, resource_uri=JEA_URI)
    assert len(pools) == 1
    assert pools[0].shell.id == JEA_SHELL_ID
    assert pools[0].shell.resource_uri == JEA_URI


def test_missing_resource_uri_is_rejected_before_connect():
    bad_shell = ET.Element("{%s}Shell" % NAMESPACES["rsp"])
    ET.SubElement(bad_shell, "{%s}ShellId" % NAMESPACES["rsp"]).text = JEA_SHELL_ID
    fake = FakeWSMan([bad_shell])

    with pytest.raises(InvalidRunspacePoolConnectionError, match="ResourceUri"):
        RunspacePool.get_runspace_pools(fake)
    # Rejection happens during enumeration, no reconnect/connect is attempted.
    assert all(c["action"] not in (WSManAction.RECONNECT, WSManAction.CONNECT) for c in fake.calls)


def test_missing_shell_id_is_rejected():
    bad_shell = ET.Element("{%s}Shell" % NAMESPACES["rsp"])
    ET.SubElement(bad_shell, "{%s}ResourceUri" % NAMESPACES["rsp"]).text = JEA_URI
    fake = FakeWSMan([bad_shell])

    with pytest.raises(InvalidRunspacePoolConnectionError, match="ShellId"):
        RunspacePool.get_runspace_pools(fake)


def test_same_shell_id_on_two_endpoints_is_ambiguous_and_rejected():
    # Interleaved/duplicated selectors: one ShellId reported by both endpoints.
    shells = [
        make_shell(JEA_SHELL_ID, JEA_URI),
        make_shell(JEA_SHELL_ID, DEFAULT_URI),
    ]
    fake = FakeWSMan(shells)

    with pytest.raises(InvalidRunspacePoolConnectionError, match="ambiguous"):
        RunspacePool.get_runspace_pools(fake)
    assert all(c["action"] not in (WSManAction.RECONNECT, WSManAction.CONNECT) for c in fake.calls)


def test_connect_without_bound_resource_uri_fails_closed():
    shells = [make_shell(JEA_SHELL_ID, JEA_URI)]
    fake = FakeWSMan(shells)

    pool = RunspacePool.get_runspace_pools(fake)[0]
    pool.shell.resource_uri = None
    with pytest.raises(InvalidRunspacePoolConnectionError, match="resource URI"):
        pool.connect()
    assert fake.calls == [] or all(
        c["action"] not in (WSManAction.RECONNECT, WSManAction.CONNECT) for c in fake.calls
    )
