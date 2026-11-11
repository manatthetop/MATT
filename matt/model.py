"""matt.model -- the ONLY module in MATT that is allowed to touch a network.

Every HTTP request this program makes, from whatever is running it, is
attributable to exactly one call in exactly one file: ``call_model`` below. It
is reachable from the CLI through one flag, ``--use-model``, and nothing imports
it at start-up to make a request. That is what keeps a default run at zero usage
tokens, and it is what lets the operator answer, under a scope agreement,
exactly what left the building.

THE SENTINEL. Older MATT notes spell the vendor sentinel ``iiiCLAUDEiii``. The
real API sentinel is ``__ANTHROPIC__``; the triple-letter form is a
transcription of it. ``resolve_endpoint`` accepts either spelling so an old
one-pager still works, and rewrites the literal ``iiiCLAUDEiii`` back to the
real sentinel before anything goes on the wire. It is never sent verbatim.

FAIL LOUD. ``--use-model`` with no endpoint and no key raises ModelConfigError
with the fix written out. No silent fallback to the local writer, because a run
that quietly skipped the model is how an operator ends up believing a summary
came from a model when it did not. And no fabricated passwords: the model
returns prose, which is stored as prose, next to the ``model_used`` tag that
says which model said it.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

__all__ = [
    "API_SENTINEL",
    "LEGACY_SENTINEL",
    "DEFAULT_MODEL",
    "DEFAULT_BASE_URL",
    "API_VERSION",
    "MAX_TOKENS",
    "TIMEOUT_SECONDS",
    "ENDPOINT_VARS",
    "KEY_VARS",
    "MODEL_VARS",
    "ModelConfigError",
    "ModelTransportError",
    "resolve_endpoint",
    "build_request",
    "call_model",
    "model_writer",
]

API_SENTINEL = "__ANTHROPIC__"
LEGACY_SENTINEL = "iiiCLAUDEiii"

DEFAULT_MODEL = "claude-sonnet-5-5"
DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"
MAX_TOKENS = 1024
TIMEOUT_SECONDS = 30.0

# environment variables resolve_endpoint consults, in priority order
ENDPOINT_VARS = ("MATT_MODEL_URL", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_BASE")
KEY_VARS = ("MATT_MODEL_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
MODEL_VARS = ("MATT_MODEL", "ANTHROPIC_MODEL")


class ModelConfigError(RuntimeError):
    """--use-model was asked for but the endpoint/key is not configured."""


class ModelTransportError(RuntimeError):
    """The endpoint was configured and reachable-ish, but the call failed."""


def resolve_endpoint(base_url: str = None, api_key: str = None, model: str = None,
                     env: dict = None) -> dict:
    """Work out where to send the request, or raise ModelConfigError.

    ``base_url`` / ``api_key`` / ``model`` win over the environment, which wins
    over the defaults -- so ``--model-url`` on a command line does the obvious
    thing. The failure cases are the point of this function:

      * an explicit base_url with no key anywhere            -> raise
      * no base_url, no key anywhere, and the caller did not
        opt into the public default endpoint with MATT_ALLOW_DEFAULT_ENDPOINT=1
                                                              -> raise

    The last one is deliberate. Defaulting to a public API endpoint and silently
    sending captured credentials there is the one mistake that turns a token
    question into a scope question.
    """
    env = dict(os.environ) if env is None else dict(env)
    base = (base_url or "").strip() or None
    for var in ENDPOINT_VARS:
        if base:
            break
        base = (env.get(var) or "").strip() or None

    key = (api_key or "").strip() or None
    for var in KEY_VARS:
        if key:
            break
        key = (env.get(var) or "").strip() or None

    name = (model or "").strip() or None
    for var in MODEL_VARS:
        if name:
            break
        name = (env.get(var) or "").strip() or None
    name = name or DEFAULT_MODEL

    if not base:
        allowed = (env.get("MATT_ALLOW_DEFAULT_ENDPOINT") or "").strip().lower()
        if key and allowed in ("1", "true", "yes", "on"):
            base = DEFAULT_BASE_URL
        else:
            raise ModelConfigError(
                "--use-model was passed but no endpoint is configured, and MATT "
                "will not guess one.\n"
                "  Set one of: " + ", ".join(ENDPOINT_VARS) + " = "
                + DEFAULT_BASE_URL + "\n"
                "  ...or pass --model-url URL, or --allow-default-endpoint\n"
                "  Either way you also need an API key: " + ", ".join(KEY_VARS)
                + ".\n"
                "  Drop --use-model to get the built-in stage2_prose writer "
                "instead, which costs zero tokens and needs nothing."
            )
    if not key:
        raise ModelConfigError(
            "--use-model was passed, an endpoint is configured (" + base + ") "
            "but no API key was found.\n"
            "  Set one of: " + ", ".join(KEY_VARS) + "\n"
            "  ...or pass --api-key KEY / --api-key-env NAME, or drop "
            "--use-model and use the built-in writer.\n"
            "  MATT will not invent a key, and it will not invent a password "
            "either: an uncracked hash stays uncracked."
        )

    base = base.rstrip("/")
    if LEGACY_SENTINEL in base:
        base = base.replace(LEGACY_SENTINEL, API_SENTINEL)
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return {"base_url": base, "api_key": key, "model": name}


def build_request(endpoint: dict, prompt: str, max_tokens: int = MAX_TOKENS) -> tuple:
    """Return (url, headers, body-dict) for one Messages call. No I/O."""
    base = endpoint["base_url"]
    url = base if base.endswith("/v1/messages") else base + "/v1/messages"
    headers = {
        "content-type": "application/json",
        "x-api-key": endpoint["api_key"],
        "anthropic-version": API_VERSION,
        "user-agent": "matt-man-at-the-top/1.0",
    }
    body = {
        "model": endpoint["model"],
        "max_tokens": int(max_tokens),
        "system": (
            "You are stage 2 of MATT, a Man At The Top credential-recovery run on "
            "an authorized network engagement. You receive decoded wire data and "
            "write short factual prose for the operator. Never invent a password: "
            "if a secret is not present in the input, say it is still an offline "
            "hash. One or two sentences, no preamble."
        ),
        "messages": [{"role": "user", "content": prompt}],
    }
    return url, headers, body


def call_model(prompt: str, base_url: str = None, api_key: str = None,
               model: str = None, max_tokens: int = MAX_TOKENS,
               timeout: float = TIMEOUT_SECONDS, env: dict = None,
               opener=None) -> str:
    """One HTTP request, one model, returning its text. THE network call.

    Nothing else in this package opens a socket. ``opener`` lets tests inject a
    transport and assert the call count without a network.
    """
    endpoint = resolve_endpoint(base_url=base_url, api_key=api_key, model=model,
                                env=env)
    url, headers, body = build_request(endpoint, prompt, max_tokens=max_tokens)
    payload = json.dumps(body).encode("utf-8")

    if opener is not None:
        raw = opener(url, headers, payload)
    else:
        request = urllib.request.Request(url, data=payload, headers=headers,
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise ModelTransportError(
                f"model endpoint returned HTTP {exc.code} for {url}: {detail}"
            ) from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise ModelTransportError(
                f"could not reach the model endpoint {url}: {exc}. Check the URL "
                "and connectivity, or drop --use-model and use the built-in writer."
            ) from exc

    try:
        data = json.loads(raw.decode("utf-8", "replace"))
        text = "".join(blk.get("text", "") for blk in data.get("content", [])
                       if blk.get("type") == "text").strip()
    except (ValueError, AttributeError) as exc:
        raise ModelTransportError(
            "model endpoint returned something that is not a Messages response: "
            f"{str(raw)[:200]!r}"
        ) from exc
    if not text:
        raise ModelTransportError(
            f"model {endpoint['model']} returned an empty completion; MATT will "
            "not substitute its own wording and label it a model result"
        )
    return text


def model_writer(**kwargs):
    """Adapt ``call_model`` to the ``finding -> prose`` shape analyze() wants.

    Pass the result as ``analyze(report, model=model_writer(...))``. Every
    finding costs exactly one request, which the operator should know before
    pointing it at a busy capture.
    """
    def writer(finding: dict) -> str:
        prompt = json.dumps(
            {
                "host": finding.get("host"),
                "protocol": finding.get("protocol"),
                "kind": finding.get("kind"),
                "hashcat_mode": finding.get("hashcat_mode"),
                "candidate": finding.get("candidate"),
            },
            ensure_ascii=False,
        )
        return call_model("Summarize this captured credential candidate for the "
                          "operator. " + prompt, **kwargs)

    return writer
