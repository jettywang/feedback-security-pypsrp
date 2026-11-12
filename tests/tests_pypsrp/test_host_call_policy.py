import threading

import pytest

from pypsrp.complex_objects import HostMethodIdentifier, PSInvocationState
from pypsrp.exceptions import HostCallDeniedError
from pypsrp.host import (
    HMI_PROMPT,
    HMI_PROMPT_FOR_CREDENTIAL2,
    HMI_READ_LINE,
    HMI_WRITE1,
    HMI_WRITE_LINE2,
    HostCallPolicy,
    PSHost,
    PSHostUserInterface,
)
from pypsrp.messages import (
    Destination,
    Message,
    MessageType,
    PipelineHostCall,
    PipelineState,
    RunspacePoolHostCall,
)
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan


class RecordingHost(PSHost):
    """A fake host that records every method actually dispatched to it."""

    def __init__(self, host_call_policy=None):
        super(RecordingHost, self).__init__(
            None, None, False, "recording-host", None, PSHostUserInterface(), "1.0",
            host_call_policy=host_call_policy,
        )
        self.calls = []
        self.lock = threading.Lock()

    def run_method(self, method_identifier, args, runspace, pipeline=None):
        # The base implementation enforces the policy before dispatching, so a
        # denied call raises HostCallDeniedError and is never recorded here.
        response = super(RecordingHost, self).run_method(
            method_identifier, args, runspace, pipeline
        )
        with self.lock:
            self.calls.append((method_identifier.value, list(args), pipeline))
        return response


class FakeShell(object):
    """Captures the PSRP fragments the runspace sends back to the server."""

    def __init__(self):
        self.sent = []
        self.lock = threading.Lock()

    def send(self, stream, fragment, **kwargs):
        with self.lock:
            self.sent.append((stream, kwargs.get("command_id"), fragment))


@pytest.fixture
def runspace():
    wsman = WSMan("")
    pool = RunspacePool(wsman)
    pool.shell = FakeShell()
    pool.host = RecordingHost(host_call_policy=HostCallPolicy.unattended())
    return pool


def host_call(pool, ci, method_value, args=None, pipeline=None):
    if pipeline is None:
        data = RunspacePoolHostCall(
            ci=ci, mi=HostMethodIdentifier(value=method_value), mp=args or []
        )
        pid = None
    else:
        data = PipelineHostCall(
            ci=ci, mi=HostMethodIdentifier(value=method_value), mp=args or []
        )
        pid = pipeline.id
    return Message(Destination.CLIENT, pool.id, pid, data, None)


def decode_responses(pool):
    raw = b"".join(fragment for _, _, fragment in pool.shell.sent)
    if not raw:
        return []
    return pool._fragmenter.defragment(raw)


class TestHostCallPolicy(object):
    def test_unattended_allows_output_but_denies_prompts_and_credentials(self):
        policy = HostCallPolicy.unattended()

        # Normal output methods remain available.
        assert policy.is_allowed(HMI_WRITE1)
        assert policy.is_allowed(HMI_WRITE_LINE2)

        # Interactive, password and credential prompts are blocked.
        assert not policy.is_allowed(HMI_READ_LINE)
        assert not policy.is_allowed(HMI_PROMPT)
        assert not policy.is_allowed(HMI_PROMPT_FOR_CREDENTIAL2)
        assert not policy.is_allowed(46)  # ReadKey

    def test_unknown_method_is_always_denied(self):
        assert not HostCallPolicy.unattended().is_allowed(999)
        # Even a permissive policy must reject identifiers it does not know.
        assert not HostCallPolicy(allow_unlisted=True).is_allowed(999)
        assert not HostCallPolicy().is_known_method(999)
        assert HostCallPolicy().is_known_method(HMI_WRITE1)

    def test_deny_wins_over_allow_and_unlisted_known_default(self):
        policy = HostCallPolicy(allow=[HMI_WRITE1], deny=[HMI_WRITE1, HMI_PROMPT])
        assert not policy.is_allowed(HMI_WRITE1)

        # Known methods not on either list follow allow_unlisted.
        permissive = HostCallPolicy()
        assert permissive.is_allowed(HMI_READ_LINE)
        strict = HostCallPolicy(allow_unlisted=False)
        assert not strict.is_allowed(HMI_READ_LINE)

    def test_check_allowed_raises_and_audits_the_denial(self):
        policy = HostCallPolicy.unattended()
        with pytest.raises(HostCallDeniedError) as err:
            policy.check_allowed(HMI_PROMPT_FOR_CREDENTIAL2)

        assert err.value.method_identifier == HMI_PROMPT_FOR_CREDENTIAL2
        assert policy.denied_calls[0][0] == HMI_PROMPT_FOR_CREDENTIAL2
        assert "denied" in policy.denied_calls[0][1]

    def test_void_method_classification(self):
        policy = HostCallPolicy.unattended()
        assert policy.is_void_method(HMI_WRITE1) is True
        assert policy.is_void_method(HMI_READ_LINE) is False

    def test_custom_allow_extends_unattended_policy(self):
        # GetName (MI 1) is a known but unlisted method the strict unattended
        # policy normally denies; a custom allow entry can open it back up.
        policy = HostCallPolicy.unattended(allow=[1])
        assert policy.is_allowed(1)
        # Credential prompts stay blocked regardless of custom allows.
        assert not policy.is_allowed(HMI_PROMPT_FOR_CREDENTIAL2)


class TestRunspaceHostCallPolicy(object):
    def test_allowed_output_runs_and_sends_no_response_for_void_method(self, runspace):
        message = host_call(runspace, ci=1, method_value=HMI_WRITE_LINE2, args=["hello"])
        result = runspace._process_runspacepool_host_call(message)

        # The fake host records the actual method invocation.
        assert runspace.host.calls[0][0] == HMI_WRITE_LINE2
        assert runspace.host.calls[0][1] == ["hello"]
        # Void methods return nothing to the server.
        assert result is message.data
        assert decode_responses(runspace) == []
        assert runspace.host.ui.stdout == ["hello\r\n"]

    def test_denied_returning_method_answers_with_error_on_same_call_id(self, runspace):
        message = host_call(runspace, ci=77, method_value=HMI_READ_LINE)
        result = runspace._process_runspacepool_host_call(message)

        # The denied method never reaches the fake host.
        assert runspace.host.calls == []
        assert result is message.data

        responses = decode_responses(runspace)
        assert len(responses) == 1
        response = responses[0]
        assert response.message_type == MessageType.RUNSPACEPOOL_HOST_RESPONSE
        assert response.data.ci == 77
        assert response.data.mi.value == HMI_READ_LINE
        assert response.data.mr is None
        assert response.data.me is not None
        assert response.data.me.fq_error == "HostCallDenied"
        assert response.data.me.category == 7
        assert str(HostMethodIdentifier(value=HMI_READ_LINE)) in response.data.me.message

    def test_denied_void_method_does_not_send_a_response(self, runspace):
        # SetShouldExit (MI 6) is a known void method denied by the strict
        # unattended policy because it is not on the allow list.
        message = host_call(runspace, ci=88, method_value=6, args=[0])
        runspace._process_runspacepool_host_call(message)

        assert runspace.host.calls == []
        assert decode_responses(runspace) == []
        assert runspace.host.host_call_policy.denied_calls[0][0] == 6

    def test_denied_unknown_method_is_rejected(self, runspace):
        message = host_call(runspace, ci=99, method_value=999)
        runspace._process_runspacepool_host_call(message)

        assert runspace.host.calls == []
        responses = decode_responses(runspace)
        # 999 is not a void method, so a rejection error is returned.
        assert len(responses) == 1
        assert responses[0].data.ci == 99
        assert "unknown" in responses[0].data.me.reason


class TestPipelineHostCallPolicy(object):
    def test_pipeline_denial_returns_pipeline_host_response_with_pipeline_id(self, runspace):
        pipeline = PowerShell(runspace)
        runspace.pipelines[pipeline.id] = pipeline

        message = host_call(
            runspace, ci=33, method_value=HMI_PROMPT_FOR_CREDENTIAL2, pipeline=pipeline
        )
        pipeline._process_pipeline_host_call(message)

        assert runspace.host.calls == []
        responses = decode_responses(runspace)
        assert len(responses) == 1
        response = responses[0]
        assert response.message_type == MessageType.PIPELINE_HOST_RESPONSE
        assert response.data.ci == 33
        assert response.data.mi.value == HMI_PROMPT_FOR_CREDENTIAL2
        assert response.data.me.fq_error == "HostCallDenied"
        # The response is routed back to the same pipeline.
        assert str(response.pid).casefold() == pipeline.id.casefold()

    def test_pipeline_allowed_output_still_invokes_the_host(self, runspace):
        pipeline = PowerShell(runspace)
        runspace.pipelines[pipeline.id] = pipeline

        message = host_call(
            runspace, ci=34, method_value=HMI_WRITE1, args=["pipeline output"], pipeline=pipeline
        )
        pipeline._process_pipeline_host_call(message)

        assert runspace.host.calls[0][0] == HMI_WRITE1
        assert runspace.host.calls[0][2] is pipeline
        assert decode_responses(runspace) == []


class TestConcurrentHostCalls(object):
    def test_concurrent_denials_keep_call_ids_associated(self, runspace):
        # Mix returning (ReadLine) and void (WriteLine2 is allowed, so use a
        # denied void method MI 6) calls across multiple threads.
        def deny_returning(ci):
            runspace._process_runspacepool_host_call(
                host_call(runspace, ci=ci, method_value=HMI_READ_LINE)
            )

        def deny_void(ci):
            runspace._process_runspacepool_host_call(
                host_call(runspace, ci=ci, method_value=6, args=[0])
            )

        threads = []
        for ci in range(100, 120):
            target = deny_returning if ci % 2 == 0 else deny_void
            threads.append(threading.Thread(target=target, args=(ci,)))

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # Every rejected returning method gets exactly one matching response.
        responses = decode_responses(runspace)
        returning_cis = [ci for ci in range(100, 120) if ci % 2 == 0]
        response_cis = sorted(response.data.ci for response in responses)
        assert response_cis == sorted(returning_cis)
        for response in responses:
            assert response.data.mi.value == HMI_READ_LINE
            assert response.data.me is not None

        # All 20 calls were refused and none reached the host.
        assert len(runspace.host.host_call_policy.denied_calls) == 20
        assert runspace.host.calls == []

    def test_normal_pipeline_completes_after_a_rejection(self, runspace):
        # First a malicious/blocked credential prompt is rejected on the
        # runspace.
        runspace._process_runspacepool_host_call(
            host_call(runspace, ci=200, method_value=HMI_PROMPT_FOR_CREDENTIAL2)
        )
        rejection = decode_responses(runspace)
        assert len(rejection) == 1
        assert rejection[0].data.me.fq_error == "HostCallDenied"

        # A separate, well behaved pipeline must still complete: its allowed
        # output host call runs and its pipeline state is processed normally.
        runspace.shell.sent.clear()
        pipeline = PowerShell(runspace)
        runspace.pipelines[pipeline.id] = pipeline

        pipeline._process_pipeline_host_call(
            host_call(runspace, ci=201, method_value=HMI_WRITE_LINE2, args=["still alive"],
                      pipeline=pipeline)
        )
        assert runspace.host.ui.stdout == ["still alive\r\n"]

        # The pipeline can still receive its completion state independently of
        # the earlier rejection.
        state_message = Message(
            Destination.CLIENT,
            runspace.id,
            pipeline.id,
            PipelineState(state=PSInvocationState.COMPLETED),
            None,
        )
        parsed = runspace._parse_responses(
            b"".join(runspace._fragmenter.fragment(state_message.data, runspace.id, pipeline.id)),
            pipeline=pipeline,
        )
        assert parsed[0][0] == MessageType.PIPELINE_STATE
        assert pipeline.state == PSInvocationState.COMPLETED
