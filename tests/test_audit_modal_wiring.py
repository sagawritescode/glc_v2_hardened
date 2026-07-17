"""B2 Modal audit-writer boundary regression tests.

These inspect both Modal's public Function spec and the actual decorator
arguments, without requiring a live deploy. A3/A4 wiring remains locked.
"""

from __future__ import annotations

import ast
import inspect


def _deployment_ast():
    import modal_app as deploy

    return deploy, ast.parse(inspect.getsource(deploy))


def _decorator_keyword(tree: ast.Module, definition_name: str, decorator_name: str, keyword: str):
    definition = next(
        node
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == definition_name
    )
    decorator = next(
        item
        for item in definition.decorator_list
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr == decorator_name
    )
    return next(item.value for item in decorator.keywords if item.arg == keyword)


def test_public_function_mounts_gateway_data_not_audit_volume():
    deploy, tree = _deployment_ast()

    assert set(deploy.fastapi_app.spec.volumes) == {"/data"}
    assert set(deploy.GATEWAY_VOLUMES) == {"/data"}
    assert deploy.audit_volume not in deploy.GATEWAY_VOLUMES.values()
    volumes_arg = _decorator_keyword(tree, "fastapi_app", "function", "volumes")
    assert isinstance(volumes_arg, ast.Name)
    assert volumes_arg.id == "GATEWAY_VOLUMES"


def test_only_writer_decorator_receives_audit_volume():
    deploy, tree = _deployment_ast()

    assert set(deploy.AUDIT_WRITER_VOLUMES) == {deploy.AUDIT_VOLUME_MOUNT}
    assert deploy.AUDIT_WRITER_VOLUMES[deploy.AUDIT_VOLUME_MOUNT] is deploy.audit_volume
    writer_volumes = _decorator_keyword(tree, "AuditWriter", "cls", "volumes")
    assert isinstance(writer_volumes, ast.Name)
    assert writer_volumes.id == "AUDIT_WRITER_VOLUMES"

    other_volume_args = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.ClassDef)) or node.name == "AuditWriter":
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            other_volume_args.extend(
                keyword.value for keyword in decorator.keywords if keyword.arg == "volumes"
            )
    assert all(
        not isinstance(arg, ast.Name) or arg.id != "AUDIT_WRITER_VOLUMES"
        for arg in other_volume_args
    )


def test_writer_interface_is_append_only_and_serialized():
    import modal_app as deploy

    assert set(deploy.AuditWriter._get_method_names()) == {"initialize", "append"}
    assert deploy.AUDIT_WRITER_MAX_CONTAINERS == 1
    assert deploy.AUDIT_WRITER_MAX_INPUTS == 1
    assert not {"update", "delete", "drop", "execute", "sql"} & set(
        deploy.AuditWriter._get_method_names()
    )


def test_public_image_and_function_have_no_audit_path_or_volume_sync():
    import modal_app as deploy

    module_src = inspect.getsource(deploy)
    image_src = module_src[module_src.index("image = (") : module_src.index("data_volume =")]
    function_src = inspect.getsource(deploy.fastapi_app.get_raw_f())
    assert "GLC_AUDIT_DB" not in image_src
    assert "GLC_AUDIT_DB" not in function_src
    assert "AUDIT_DB_PATH" not in function_src
    assert "audit_volume" not in function_src
    assert "register_volume_sync" not in function_src
    assert "register_remote_backend" in function_src
    assert "initialize=initialize_remote_audit" in function_src
    assert "append=append_remote_audit" in function_src


def test_production_callbacks_call_remote_writer(monkeypatch):
    import modal_app as deploy

    calls = []

    class RemoteMethod:
        def __init__(self, name):
            self.name = name

        def remote(self, *args):
            calls.append((self.name, args))
            return 41

    class FakeWriter:
        initialize = RemoteMethod("initialize")
        append = RemoteMethod("append")

    monkeypatch.setattr(deploy, "audit_writer", FakeWriter())
    event = {"channel": "x"}
    deploy.initialize_remote_audit()
    assert deploy.append_remote_audit(event) == 41
    assert calls == [("initialize", ()), ("append", (event,))]


def test_adapter_and_a3_sandbox_wiring_never_mount_audit_volume():
    import modal_app as deploy

    kwargs = deploy.build_sandbox_egress_client().sandbox_create_kwargs()
    assert "volumes" not in kwargs
    assert deploy.AUDIT_VOLUME_MOUNT not in kwargs.get("volumes", {})
    assert kwargs["outbound_domain_allowlist"] == list(deploy.PROVIDER_EGRESS_ALLOWLIST)
    # Webhook adapters execute in the public Function, whose only declared
    # mount is gateway config data; external adapters receive no Modal mount.
    assert set(deploy.fastapi_app.spec.volumes) == {"/data"}


def test_modal_function_secrets_unchanged():
    """A4 regression: Function mounts auth only; Sandbox mounts provider keys."""
    import modal_app as deploy

    assert deploy.FUNCTION_SECRETS == [deploy.auth_secret]
    assert deploy.llm_secret not in deploy.FUNCTION_SECRETS
    assert deploy.SANDBOX_SECRETS == [deploy.llm_secret]
